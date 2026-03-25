from __future__ import annotations

import sys

import requests

from .cli import main as cli_main


def main() -> int:
    try:
        return cli_main()
    except requests.HTTPError as exc:
        print(f"[error] HTTP failure: {exc}", file=sys.stderr)
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
    return 1
