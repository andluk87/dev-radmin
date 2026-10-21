#!/usr/bin/env python3
"""Fetch the public Microsoft CP1252 mapping used by the limited research runtime."""

import argparse
import hashlib
import urllib.request
from pathlib import Path

URL = "https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WindowsBestFit/bestfit1252.txt"
SHA256 = "72ea23c939c5b26fae7aded0207b327e2f3902d7d3c168d7087f5cfc38ee76a9"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with urllib.request.urlopen(URL, timeout=30) as response:
        data = response.read(100000)
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("mapping checksum mismatch")
    with args.output.open("xb") as target:
        target.write(data)
    print("Verified mapping saved to", args.output)


if __name__ == "__main__":
    main()
