#!/usr/bin/env python3
"""Extract a license-bound file's dynamic-key mask.

Thin wrapper around ``ioncube-re license-key``; the implementation and its
caveats live in :mod:`ioncube_re.license_key`.  Requires the ionCube Loader
and a valid license, and runs the encoded file's top level through the
loader.  Prints the mask (e.g. ``0x00363de0``).
"""
import sys

from ioncube_re.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["license-key", *sys.argv[1:]]))
