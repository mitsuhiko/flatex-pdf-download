import re
import os
import json
import click
import requests
import posixpath
from urllib.parse import urljoin, urlparse
from datetime import date, timedelta


URL_BASE = "https://konto.flatex.at/banking-flatex.at/"
SSO_URL = "https://www.flatex.at/sso"

_token_re = re.compile(r'\bwebcore\.setTokenId\s*\(\s*"(.*?)"')
_download_re = re.compile(
    r'\bDownloadDocumentBrowserBehaviorsClick\.finished\((".*?\.pdf")'
)


def _format_date(d):
    return d.strftime("%d.%m.%Y")


def _iter_dates(start, end):
    ptr = end
    while ptr >= start:
        ptr -= timedelta(days=14)
        yield max(ptr, start), end
        end = ptr


class Fetcher(object):
    def __init__(self, session_id=None):
        self.session_id = session_id
        self.window_id = None
        self.token_id = None
        self.session = requests.Session()

    def login(self, user_id, password):
        self.session.post(
            SSO_URL,
            data={
                "tx_flatexaccounts_singlesignonbanking[uname_app]": str(user_id),
                "tx_flatexaccounts_singlesignonbanking[password_app]": password,
                "tx_flatexaccounts_singlesignonbanking[sessionpass]": "",
            },
        )

    def _request(self, url, data):
        url = urljoin(URL_BASE, url)
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "X-windowId": self.window_id or "x",
            "X-tokenId": self.token_id or "x",
            "Accept": "*/*",
            "X-AJAX": "true",
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

        return resp.json()

    def _archive_list_request(self, data):
        return self._request(
            "documentArchiveListFormAction.do",
            {
                "dateRangeComponent.startDate.text": "26.06.2021",
                "dateRangeComponent.endDate.text": "26.07.2021",
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
                    download = _download_re.search(command["script"])
                    if download is not None:
                        yield urljoin(URL_BASE, json.loads(download.group(1)))
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
        if self.session_id is not None:
            cookies = {"JSESSIONID": self.session_id}
        return self.session.get(urljoin(URL_BASE, url), cookies=cookies)

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


@click.command()
@click.option("--session-id", help="the optional session id from flatex (JSESSIONID)")
@click.option("-u", "--userid", help="the user ID to use for sign-in")
@click.option("-p", "--password", help="the password to use for sign-in")
@click.option(
    "-o",
    "--output",
    help="The output folder where PDFs go",
    default="pdfs",
    show_default=True,
)
@click.option(
    "--days", help="How many days of PDFs to download", default=90, show_default=True
)
def cli(session_id, userid, password, output, days):
    """A utility to download PDFs from flatex.at"""
    fetcher = Fetcher(session_id)
    if userid:
        if not password:
            password = click.prompt("password", hide_input=True)
        fetcher.login(userid, password)
    fetcher.download_all(output, days=days)


if __name__ == "__main__":
    cli()
