#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "click>=8.1",
#     "requests>=2.32",
# ]
# ///
"""A utility to download PDFs (and CSVs) from flatex.at / flatex.de."""

import html
import json
import posixpath
import re
import struct
import sys
import time
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urljoin, urlparse

import click
import requests

PORTALS = {
    "at": {"url_base": "https://konto.flatex.at/banking-flatex.at/"},
    "de": {"url_base": "https://konto.flatex.de/banking-flatex/"},
}
DEFAULT_PORTAL = "at"

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)
# The login app decides based on the reported screen size whether to send
# the user to the classic banking UI or to "flatex next".  Large screens get
# sent to flatex next which this script does not support, so we pretend to
# be a small browser window.
SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600
DEVICE_DETAILS = {
    "platform": "MacIntel",
    "browserName": "chrome",
    "browserVersion": "140.0.0.0",
    "screenWidth": str(SCREEN_WIDTH),
    "screenHeight": str(SCREEN_HEIGHT),
}

_token_re = re.compile(r'\bwebcore\.setTokenId\s*\(\s*"(.*?)"')
_window_re = re.compile(r'\bsetCurrentWindowId\s*\(\s*"(.*?)"')
_pdf_download_re = re.compile(r'DocumentViewer\.display\((".*?\.pdf")')
_csv_download_re = re.compile(r'DocumentViewer\.display\((".*?\.csv")')
_server_error_re = re.compile(
    r'<li class="ServerResponseError"[^>]*>(.*?)</li>', re.DOTALL
)
_tag_re = re.compile(r"<[^>]+>")

debug_enabled = False


def debug(msg):
    if debug_enabled:
        click.echo(f"[debug] {msg}", err=True)


def _format_date(d):
    return d.strftime("%d.%m.%Y")


def _iter_dates(start, end):
    ptr = end
    while ptr >= start:
        ptr -= timedelta(days=14)
        yield max(ptr, start), end
        end = ptr


def _extract_server_errors(text):
    rv = []
    for match in _server_error_re.finditer(text):
        msg = _tag_re.sub(" ", match.group(1).replace("<br>", "\n"))
        msg = html.unescape(re.sub(r"[ \t]+", " ", msg))
        msg = "\n".join(line.strip() for line in msg.splitlines() if line.strip())
        rv.append(msg)
    return rv


_U64 = 0xFFFFFFFFFFFFFFFF
_myra_nonce_re = re.compile(r'findNonce\(\s*"([^"]+)"\s*,\s*(\d+)\s*,\s*(\d+)')
_myra_result_re = re.compile(
    r'"(/x-myracloud-proof-result/)"\s*\+\s*\w+\s*\+\s*"([^"]*)"'
)


def _rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & _U64


def _siphash24(key, msg):
    k0, k1 = struct.unpack("<QQ", key)
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    def rounds(count):
        nonlocal v0, v1, v2, v3
        for _ in range(count):
            v0 = (v0 + v1) & _U64
            v1 = _rotl(v1, 13) ^ v0
            v0 = _rotl(v0, 32)
            v2 = (v2 + v3) & _U64
            v3 = _rotl(v3, 16) ^ v2
            v0 = (v0 + v3) & _U64
            v3 = _rotl(v3, 21) ^ v0
            v2 = (v2 + v1) & _U64
            v1 = _rotl(v1, 17) ^ v2
            v2 = _rotl(v2, 32)

    end = len(msg) - len(msg) % 8
    for i in range(0, end, 8):
        (m,) = struct.unpack_from("<Q", msg, i)
        v3 ^= m
        rounds(2)
        v0 ^= m
    b = (len(msg) << 56) | int.from_bytes(msg[end:], "little")
    v3 ^= b
    rounds(2)
    v0 ^= b
    v2 ^= 0xFF
    rounds(4)
    return v0 ^ v1 ^ v2 ^ v3


def _solve_myra_challenge(key, target, limit):
    """Solves the proof of work of the Myra CDN's browser check
    (/x-myracloud/proof2.js): find the first nonce whose SipHash-2-4 folded
    to 32 bits is below the target."""
    key = key.encode("latin-1")
    for nonce in range(limit):
        rv = _siphash24(key, b"\x00" + nonce.to_bytes(3, "big"))
        if ((rv ^ (rv >> 32)) & 0xFFFFFFFF) < target:
            return nonce
    return limit


class Session(requests.Session):
    """A requests session that transparently passes the Myra CDN browser
    check which kicks in after a burst of requests."""

    def request(self, method, url, *args, **kwargs):
        for _ in range(3):
            resp = super().request(method, url, *args, **kwargs)
            if resp.status_code != 503:
                break
            nonce_args = _myra_nonce_re.search(resp.text)
            result_url = _myra_result_re.search(resp.text)
            if nonce_args is None or result_url is None:
                break
            key, target, limit = nonce_args.groups()
            nonce = _solve_myra_challenge(key, int(target), int(limit))
            debug(f"solved CDN browser check for {url} (nonce={nonce})")
            super().request(
                "GET",
                urljoin(url, result_url.group(1) + str(nonce) + result_url.group(2)),
                allow_redirects=False,
            )
        return resp


class LoginError(click.ClickException):
    pass


class WebcoreApp:
    """Speaks the ajax protocol of flatex's "webcore" web framework.

    Both the banking frontend and the login frontend are separate webcore
    applications which each track their own window and token id.
    """

    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.window_id = None
        self.token_id = None

    def _headers(self, ajax="true"):
        return {
            "X-Requested-With": "XMLHttpRequest",
            "X-AJAX": ajax,
            "X-windowId": self.window_id or "",
            "X-tokenId": self.token_id or "undefined",
            "Accept": "*/*",
        }

    def _update_from_page(self, content):
        tokens = _token_re.findall(content)
        if tokens:
            self.token_id = tokens[-1]
        windows = _window_re.findall(content)
        if windows:
            self.window_id = windows[-1]

    def _handle_response(self, resp):
        resp.raise_for_status()
        window_id = resp.headers.get("X-windowId")
        if window_id:
            self.window_id = window_id
        try:
            commands = resp.json().get("commands", [])
        except ValueError:
            self._update_from_page(resp.text)
            commands = [{"command": "fullPageReplace", "content": resp.text}]

        for command in commands:
            if command["command"] == "fullPageReplace":
                if "content" not in command and "fetchLocation" in command:
                    page = self.session.get(
                        urljoin(self.base_url, command["fetchLocation"]),
                        headers=self._headers(),
                    )
                    command["content"] = page.text
                self._update_from_page(command.get("content", ""))
            if "windowId" in command:
                self.window_id = command["windowId"]
            extra = (
                command.get("location")
                or command.get("url")
                or command.get("script", "")[:200]
            )
            debug(f"{resp.request.method} {resp.url} -> {command['command']} {extra}")
        return commands

    def boot(self, page, previous_window_id=None):
        """Performs the same startup dance a browser does when loading a page.

        `previous_window_id` is the window id of the app the browser was on
        before; the login app uses it to decide which system to send the
        user back to.
        """
        resp = self.session.get(urljoin(self.base_url, page))
        resp.raise_for_status()
        # the entry URL might redirect (eg: to attach a window id), the page
        # we then load via ajax is the final one.
        page = resp.url
        self._update_from_page(resp.text)
        resp = self.session.post(
            urljoin(self.base_url, "ajaxCommandServlet"),
            headers=self._headers(),
            data={
                "command": "engineStartUp",
                "windowIdPreviouslyUsed": previous_window_id or "",
                "deviceData": json.dumps(
                    {
                        "windowWidth": SCREEN_WIDTH,
                        "windowHeight": SCREEN_HEIGHT - 143,
                        "screenWidth": SCREEN_WIDTH,
                        "screenHeight": SCREEN_HEIGHT,
                        "userAgent": USER_AGENT,
                        "browserName": "chrome",
                        "browserVersion": "140.0.0.0",
                        "platform": "MacIntel",
                        "touchDevice": False,
                        "pdfSupport": True,
                        "time": int(time.time() * 1000),
                    }
                ),
            },
        )
        resp.raise_for_status()
        if resp.headers.get("X-windowId"):
            self.window_id = resp.headers["X-windowId"]
        self.token_id = None
        return self.get(page)

    def get(self, page, ajax="true"):
        return self._handle_response(
            self.session.get(urljoin(self.base_url, page), headers=self._headers(ajax))
        )

    def command(self, name, **data):
        return self._handle_response(
            self.session.post(
                urljoin(self.base_url, "ajaxCommandServlet"),
                headers=self._headers(),
                data={"command": name, **data},
            )
        )

    def submit(self, action, data):
        # the browser submits forms as multipart/form-data
        files = [(key, (None, str(value))) for key, value in data.items()]
        return self._handle_response(
            self.session.post(
                urljoin(self.base_url, action), headers=self._headers(), files=files
            )
        )


class Fetcher:
    def __init__(self, session_id=None, portal=None):
        self.portal = portal or DEFAULT_PORTAL
        self.session = Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.banking = WebcoreApp(self.session, self.url_base)
        self.banking_booted = False
        if session_id is not None:
            self.session.cookies.set(
                "JSESSIONID",
                session_id,
                domain=urlparse(self.url_base).hostname,
                path=urlparse(self.url_base).path.rstrip("/"),
            )

    @property
    def url_base(self):
        return PORTALS[self.portal]["url_base"]

    def is_logged_in(self):
        resp = self.session.get(
            urljoin(self.url_base, "checkLogin"), headers=self.banking._headers("false")
        )
        try:
            return bool(resp.json().get("loggedIn"))
        except ValueError:
            return False

    def _find_login_app(self):
        """Returns the login app's base URL and the entry URL the banking app
        redirects to.  The entry URL carries the banking window id which is
        how the login app knows to send us back to the classic banking UI
        (rather than "flatex next")."""
        commands = self.banking.boot("loginFormAction.do")
        for command in commands:
            if command["command"] == "redirect":
                entry_url = command["location"]
                location = urlparse(entry_url)
                base = f"{location.scheme}://{location.netloc}{location.path}"
                if not base.endswith("/"):
                    base = posixpath.dirname(base) + "/"
                return base, entry_url
        raise LoginError("could not discover the flatex login application")

    def login(self, user_id, password):
        login_base, entry_url = self._find_login_app()
        login = WebcoreApp(self.session, login_base)
        debug(f"login app at {login.base_url}")
        login.boot(entry_url, previous_window_id=self.banking.window_id)
        login.command("processCommandQueue")
        login.submit("checkLoginFormAction.do", {"btnOpenLoginForm.clicked": "true"})
        login.command("processCommandQueue")

        commands = login.submit(
            "loginFormAction.do",
            {
                "txtUserId.text": str(user_id),
                "txtPassword.txtPassword.text": password,
                "chkSessionPassword.checked": "off",
                "btnLogin.clicked": "true",
            },
        )
        wf_login = next((c for c in commands if c["command"] == "wfLogin"), None)
        if wf_login is None:
            errors = _extract_server_errors(json.dumps(commands))
            raise LoginError("\n".join(errors) or "login form was not accepted")

        debug(f"wfLogin: loginUrl={wf_login['loginUrl']} baseUrl={wf_login['baseUrl']}")
        resp = self.session.post(
            wf_login["loginUrl"],
            headers=login._headers("false"),
            data={**wf_login["loginParameters"], **DEVICE_DETAILS},
        )
        resp.raise_for_status()
        login_response = resp.text
        try:
            status = json.loads(login_response)
        except ValueError:
            status = {}
        debug(f"login status: {status.get('status')!r} {status.get('error')!r}")

        commands = login.command(
            "loginResponse",
            formName="loginForm",
            baseUrl=wf_login["baseUrl"],
            loginResponse=login_response,
        )
        if status.get("status") == "fail":
            raise LoginError(
                status.get("errorText")
                or "\n".join(_extract_server_errors(json.dumps(commands)))
                or f"login failed (error {status.get('error')})"
            )

        # on success the login app tells the browser to navigate to the
        # banking app's login progress page which finalizes the session.
        target = status.get("target")
        if target:
            if not wf_login["baseUrl"].startswith(self.url_base):
                raise LoginError(
                    f"login was routed to {wf_login['baseUrl']} instead of the "
                    "classic banking app"
                )
            self.banking.boot(target.lstrip("/"), previous_window_id=login.window_id)
            self.banking.command("processCommandQueue")
            self.banking.command("resumeLogin")
            self.banking_booted = True

        if not self.is_logged_in():
            errors = _extract_server_errors(json.dumps(commands))
            raise LoginError(
                "\n".join(errors)
                or "login did not complete (maybe a second factor is required?); "
                "re-run with --debug for details"
            )

    def _ensure_banking(self):
        if not self.banking_booted:
            self.banking.boot("")
            self.banking_booted = True
            if not self.is_logged_in():
                raise click.ClickException(
                    "not logged in; provide --userid or a valid --session-id"
                )

    def _archive_list_request(self, data):
        return self.banking.submit(
            "documentArchiveListFormAction.do",
            {
                "accountSelection.account.selecteditemindex": "0",
                "documentCategory.selecteditemindex": "0",
                "readState.selecteditemindex": "0",
                # 6 = "Individueller Zeitraum" (custom date range)
                "dateRangeComponent.retrievalPeriodSelection.selecteditemindex": "6",
                "storeSettings.checked": "off",
                **data,
            },
        )

    def iter_download_urls(self, start_date, end_date):
        data = {
            "dateRangeComponent.startDate.text": _format_date(start_date),
            "dateRangeComponent.endDate.text": _format_date(end_date),
        }

        self._archive_list_request({"applyFilterButton.clicked": "true", **data})

        idx = 0
        while True:
            found = False
            commands = self._archive_list_request(
                {"documentArchiveListTable.selectedrowidx": str(idx), **data}
            )
            for command in commands:
                if command["command"] == "execute":
                    download = _pdf_download_re.search(command["script"])
                    if download is not None:
                        yield urljoin(self.url_base, json.loads(download.group(1)))
                        found = True
                        break

            if not found:
                break
            idx += 1

    def iter_all_download_urls(self, start_date=None, end_date=None, days=None):
        if end_date is None:
            end_date = date.today()
        if days is not None:
            start_date = end_date - timedelta(days=days)
        if start_date is None:
            raise TypeError("no start date")

        self._ensure_banking()
        self.banking.get("documentArchiveListFormAction.do")
        for start, end in _iter_dates(start_date, end_date):
            yield from self.iter_download_urls(start, end)

    def download_file(self, url):
        return self.session.get(urljoin(self.url_base, url))

    def download_all(self, target_folder, **kwargs):
        target_folder = Path(target_folder)
        target_folder.mkdir(parents=True, exist_ok=True)

        for url in self.iter_all_download_urls(**kwargs):
            filename = posixpath.basename(urlparse(url).path)
            target_file = target_folder / filename
            if target_file.is_file():
                status = "X"
            else:
                status = "A"
                with self.download_file(url) as resp:
                    if b"checking your browser for security issues" in resp.content:
                        status = "?"
                    else:
                        target_file.write_bytes(resp.content)
            click.echo(f"{status} {filename}")

    def download_csv(self, csv, start_date=None, end_date=None, days=None):
        if csv == "transactions":
            endpoint = "depositTransactionsFormAction.do"
            form = "depositTransactionsForm"
        elif csv == "account":
            endpoint = "accountPostingsFormAction.do"
            form = "accountPostingsForm"
        else:
            raise TypeError("unknown csv")

        if end_date is None:
            end_date = date.today()
        if days is not None:
            start_date = end_date - timedelta(days=days)
        if start_date is None:
            raise TypeError("no start date")

        self._ensure_banking()
        self.banking.get(endpoint)
        self.banking.submit(
            endpoint,
            {
                "dateRangeComponent.startDate.text": _format_date(start_date),
                "dateRangeComponent.endDate.text": _format_date(end_date),
                "depositSelection.deposit.selecteditemindex": "0",
                "searchType.selecteditemindex": "0",
                # 5 = "Individueller Zeitraum" (custom date range)
                "dateRangeComponent.retrievalPeriodSelection.selecteditemindex": "5",
                "applyFilterButton.clicked": "true",
            },
        )

        commands = self.banking.command(
            "triggerAction",
            delay="0",
            eventData=json.dumps({"button": 0, "value": ""}),
            eventType="click",
            formName=form,
            widgetId=form + "_tableActionCombobox_entriesI1I",
            widgetName="tableActionCombobox.entries[1]",
        )
        for command in commands:
            if command["command"] == "execute":
                match = _csv_download_re.search(command["script"])
                if match is not None:
                    url = urljoin(self.url_base, json.loads(match.group(1)))
                    with self.download_file(url) as resp:
                        return resp.content


@click.command()
@click.option("--session-id", help="An optional session id from flatex (JSESSIONID).")
@click.option(
    "-u", "--userid", envvar="FLATEX_USERID", help="The user ID to sign in with."
)
@click.option(
    "-p",
    "--password",
    envvar="FLATEX_PASSWORD",
    help="The password to sign in with (prompted if not given).",
)
@click.option(
    "--csv",
    help="Download a CSV and print to stdout instead.",
    type=click.Choice(["transactions", "account"]),
)
@click.option(
    "-o",
    "--output",
    help="The output folder where PDFs go.",
    default="pdfs",
    show_default=True,
)
@click.option(
    "--portal",
    help="Which flatex portal to use.",
    default=DEFAULT_PORTAL,
    show_default=True,
    type=click.Choice(sorted(PORTALS)),
)
@click.option(
    "--days", help="How many days of PDFs to download.", default=90, show_default=True
)
@click.option(
    "--debug", "debug_flag", is_flag=True, help="Log protocol details to stderr."
)
def cli(session_id, userid, password, output, portal, days, csv, debug_flag):
    """A utility to download PDFs from flatex.at and flatex.de.

    The default behavior is to download PDFs but optionally with --csv
    one can get one of the two CSV types ("transactions" for a list of
    transactions or "account" for the account overview) instead.
    """
    global debug_enabled
    debug_enabled = debug_flag

    fetcher = Fetcher(session_id, portal=portal)
    if userid:
        if not password:
            password = click.prompt("password", hide_input=True)
        fetcher.login(userid, password)
    elif not session_id:
        raise click.UsageError("either --userid or --session-id is required")

    if csv:
        downloaded = fetcher.download_csv(csv, days=days)
        if downloaded is None:
            raise click.ClickException("could not download CSV")
        sys.stdout.buffer.write(downloaded)
    else:
        fetcher.download_all(output, days=days)


if __name__ == "__main__":
    cli()
