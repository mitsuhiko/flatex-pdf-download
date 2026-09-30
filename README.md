# flatex-pdf-download

This repository contains a pretty crappy python script to download PDFs
from flatex.at and flatex.de.

## How to Run

The script is a self-contained [uv](https://docs.astral.sh/uv/) script, so
dependencies are installed automatically:

```
./flatex-fetch.py --help
```

or

```
uv run flatex-fetch.py --help
```

Example:

```
./flatex-fetch.py -u 1234567 --days 365 -o pdfs
```

The user ID and password can also be provided via the `FLATEX_USERID` and
`FLATEX_PASSWORD` environment variables.  If something goes wrong, pass
`--debug` to see the protocol exchange with flatex.
