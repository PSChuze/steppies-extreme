#!/usr/bin/env python3
"""Extreme 2 DNAS bypass -- patches a loose copy of SLUS_211.74.

The bytes come from patches/patches.json, the same manifest tools/isopatch.py
uses, so this cannot drift out of step with the disc patch.  Use this only when
you already have the ELF extracted; to patch a disc image use isopatch.py.

Verifies every original word before writing.  Never patches in place.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isopatch

SERIAL, FNAME = 'SLUS-21174', 'SLUS_211.74'

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit("usage: elfpatch.py <SLUS_211.74> <out.SLUS_211.74>")
    isopatch.patch_loose(SERIAL, FNAME, sys.argv[1], sys.argv[2])
