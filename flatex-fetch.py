import re
import os
import json
import time
import click
import requests
import random
import posixpath
from urllib.parse import urljoin, urlparse
from datetime import date, timedelta


PORTALS = {
    "at": {
        "url_base": "https://konto.flatex.at/banking-flatex.at/",
        "sso_url": "https://www.flatex.at/sso",
    },
    "de": {
        "url_base": "https://konto.flatex.de/banking-flatex/",
        "sso_url": "https://www.flatex.de/sso",
    },
}
DEFAULT_PORTAL = "at"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"

_token_re = re.compile(r'\bwebcore\.setTokenId\s*\(\s*"(.*?)"')
_pdf_download_re = re.compile(r'DocumentViewer\.display\((".*?\.pdf")')
_csv_download_re = re.compile(r'DocumentViewer\.display\((".*?\.csv")')


def _format_date(d):
    return d.strftime("%d.%m.%Y")


def _iter_dates(start, end):
    ptr = end
    while ptr >= start:
        ptr -= timedelta(days=14)
        yield max(ptr, start), end
        end = ptr


class Fetcher(object):
    def __init__(self, session_id=None, portal=None, wait=False):
        if portal is None:
            portal = DEFAULT_PORTAL
        self.session_id = session_id
        self.window_id = None
        self.token_id = None
        self.portal = portal
        self.session = requests.Session()
        self.wait = wait

    @property
    def url_base(self):
        return PORTALS[self.portal]["url_base"]

    @property
    def sso_url(self):
        return PORTALS[self.portal]["sso_url"]

    def login(self, user_id, password):
        self.session.post(
            self.sso_url,
            headers={"User-Agent": USER_AGENT},
            data={
                "tx_flatexaccounts_singlesignonbanking[uname_app]": str(user_id),
                "tx_flatexaccounts_singlesignonbanking[password_app]": password,
                "tx_flatexaccounts_singlesignonbanking[sessionpass]": "",
            },
        )

    def _request(self, url, data):
        url = urljoin(self.url_base, url)
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "X-windowId": self.window_id or "x",
            "X-tokenId": self.token_id or "x",
            "Accept": "*/*",
            "X-AJAX": "true",
            "User-Agent": USER_AGENT,
        }

        if self.session_id is not None:
            cookies = {
                "JSESSIONID": self.session_id,
                "sessionLength": "1800",
            }
        else:
            cookies = None

        resp = self.session.post(
            url,
            cookies=cookies,
            headers=headers,
            data=data,
        )

        json = resp.json()
        for command in json["commands"]:
            if command["command"] == "fullPageReplace":
                token = _token_re.search(command["content"])
                if token is not None:
                    self.token_id = token.group(1)
            if "windowId" in command:
                self.window_id = command["windowId"]

        return json

    def _archive_list_request(self, data):
        return self._request(
            "documentArchiveListFormAction.do",
            {
                "accountSelection.account.selecteditemindex": "0",
                "documentCategory.selecteditemindex": "0",
                "readState.selecteditemindex": "0",
                "dateRangeComponent.retrievalPeriodSelection.selecteditemindex": "5",
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
            rv = self._archive_list_request(
                {
                    "documentArchiveListTable.selectedrowidx": str(idx),
                    **data,
                }
            )

            for command in rv["commands"]:
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

        for start_date, end_date in _iter_dates(start_date, end_date):
            for url in self.iter_download_urls(start_date, end_date):
                yield url

    def download_file(self, url):
        cookies = None
        self.session.headers = {"User-Agent": USER_AGENT}
        if self.session_id is not None:
            cookies = {"JSESSIONID": self.session_id}
        return self.session.get(urljoin(self.url_base, url), cookies=cookies)

    def download_all(self, target_folder, **kwargs):
        try:
            os.makedirs(target_folder)
        except OSError:
            pass

        for url in self.iter_all_download_urls(**kwargs):
            filename = posixpath.basename(urlparse(url).path)
            target_file = os.path.join(target_folder, filename)
            if os.path.isfile(target_file):
                status = "X"
            else:
                status = "A"
                with self.download_file(url) as resp:
                    if (
                        b"Please wait while we are checking your browser for security issues"
                        in resp.content
                    ):
                        status = "?"
                    else:
                        with open(target_file, "wb") as df:
                            df.write(resp.content)
            print(f"{status} {filename}")
            if self.wait:
                time.sleep(random.randint(2, 6))

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

        self._request(
            endpoint,
            {
                "dateRangeComponent.startDate.text": _format_date(start_date),
                "dateRangeComponent.endDate.text": _format_date(end_date),
                "depositSelection.deposit.selecteditemindex": "0",
                "searchType.selecteditemindex": "0",
                "dateRangeComponent.retrievalPeriodSelection.selecteditemindex": "5",
            },
        )

        rv = self._request(
            "ajaxCommandServlet",
            {
                "command": "triggerAction",
                "delay": "0",
                "eventData": json.dumps({"button": 0, "value": ""}),
                "eventType": "click",
                "formName": form,
                "widgetId": form + "_tableActionCombobox_entriesI1I",
                "widgetName": "tableActionCombobox.entries[1]",
            },
        )
        for command in rv["commands"]:
            if command["command"] == "execute":
                match = _csv_download_re.search(command["script"])
                if match is not None:
                    url = urljoin(self.url_base, json.loads(match.group(1)))
                    with self.download_file(url) as resp:
                        return resp.content


@click.command()
@click.option("--session-id", help="the optional session id from flatex (JSESSIONID)")
@click.option("-u", "--userid", help="the user ID to use for sign-in")
@click.option("-p", "--password", help="the password to use for sign-in")
@click.option(
    "--csv",
    help="Download a CSV and print to stdout instead",
    type=click.Choice(["transactions", "account"]),
)
@click.option(
    "-o",
    "--output",
    help="The output folder where PDFs go",
    default="pdfs",
    show_default=True,
)
@click.option(
    "--portal",
    help="Which Flatex portal to use",
    default=DEFAULT_PORTAL,
    show_default=True,
    type=click.Choice(sorted(PORTALS.keys())),
)
@click.option(
    "--days", help="How many days of PDFs to download", default=90, show_default=True
)
@click.option(
    "--wait", help="Wait for a random number of seconds between fetches", show_default=True,
    default=False, type=bool)
def cli(session_id, userid, password, output, portal, days, csv, wait):
    """A utility to download PDFs from flatex.at.

    The default behavior is to download PDFs but optionally with --csv
    one can get one of the two CSV types ("transactions" for a list of
    tranasctions or "account" for the account overview) instead.
    """
    fetcher = Fetcher(session_id, portal=portal, wait=wait)
    if userid:
        if not password:
            password = click.prompt("password", hide_input=True)
        fetcher.login(userid, password)
    if csv:
        downloaded = fetcher.download_csv(csv, days=days)
        if downloaded is not None:
            click.echo(downloaded)
        else:
            click.abort("")
    else:
        fetcher.download_all(output, days=days)


if __name__ == "__main__":
    cli()
