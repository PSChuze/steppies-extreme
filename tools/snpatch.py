#!/usr/bin/env python3
"""SuperNOVA DNAS2 bypass -- patches a loose net_mas4 (DATA03.BIN).

Forces the DNAS scene's state-10 handler to report sceDNAS2 result type 5
("Authenticated.") without ever consulting the DNAS2 library, then lets the
game's own code fall through to state 0x0b (finished).

The bytes come from patches/patches.json, the same manifest tools/isopatch.py
uses, so this cannot drift out of step with the disc patch.  Use this only when
you already have DATA03.BIN extracted; to patch a disc image use isopatch.py.

Verifies every original word before writing.  Never patches in place.
"""
import os, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isopatch

SERIAL, FNAME = 'SLUS-21377', 'DATA03.BIN'


def main(src, dst):
    spec = isopatch.load()['games'][SERIAL]['files'][FNAME]
    want = int(spec['load_vaddr'], 16)
    with open(src, 'rb') as f:
        head = f.read(12)
    if head[:4] != b'MWo3':
        sys.exit("not an overlay module (bad magic)")
    load = struct.unpack_from('<I', head, 8)[0]
    if load != want:
        sys.exit("unexpected load address %08x (want %08x)" % (load, want))

    isopatch.patch_loose(SERIAL, FNAME, src, dst)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit("usage: snpatch.py <in DATA03.BIN> <out DATA03.BIN>")
    main(sys.argv[1], sys.argv[2])
