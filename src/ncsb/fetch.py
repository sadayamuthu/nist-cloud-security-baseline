"""Download the pre-built NCSB catalog from openastra.org."""

from __future__ import annotations

import argparse
import json

import requests

NCSB_CATALOG_URL = "https://openastra.org/ncsb/catalog/v0.1/latest.json"


def main(args: argparse.Namespace) -> None:
    print(f"Fetching catalog from {NCSB_CATALOG_URL} ...")
    r = requests.get(NCSB_CATALOG_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"Wrote {data['count']} controls to {args.out}")
