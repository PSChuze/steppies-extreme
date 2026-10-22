#!/usr/bin/env python3
"""Copy the games' login key out of your own disc, for the account link.

A DDR login reaches the gate enciphered: the client sends its name and an MD5
of name and password, both under Blowfish with one 56-byte key the three games
share (docs/protocol.md, "Login"). The gate only ever compares what it is
sent, so it never needs the key. The account link does (server/ddrlink.py):
to check a password typed on a website it has to encipher it the way the game
would.

That key is Konami's, so it is not in this repository. This reads it from any
one of the three discs and writes it to a file the link loads at start:

    python3 tools/loginkey.py "DDR SuperNOVA (USA).iso" state/loginkey.bin

Clean and patched images both work; the patch does not touch the key. The
result is checked by enciphering a block of zeros, which has a known answer,
before anything is written.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, os.pardir, 'server'))
sys.path.insert(0, HERE)

import ddrlink                                    # noqa: E402  (server/)
from boardart import iso_files                    # noqa: E402  (server/)

KEY_LEN = 56

#: Where each game keeps the key: (file on the disc, byte offset).
#:   Extreme 2    DATA/DATA07.BIN, the network overlay, stored unpacked
#:   SuperNOVA    SLUS_213.77, VA 0x002cfd20, copied out at 0x0026a540
#:   SuperNOVA 2  SLUS_216.08, the same table rebuilt
PLACES = (('DATA/DATA07.BIN', 0x1a030), ('SLUS_213.77', 0x1cffa0),
          ('SLUS_216.08', 0x2010e0))


def from_iso(path):
    """The key from a disc image, or None when this is not one of the three
    games."""
    with open(path, 'rb') as f:
        try:
            names = iso_files(f)
        except ValueError:
            return None
        for name, off in PLACES:
            if name not in names:
                continue
            start, size = names[name]
            if off + KEY_LEN > size:
                continue
            f.seek(start + off)
            key = f.read(KEY_LEN)
            if ddrlink.key_ok(key):
                return key
    return None


def main(argv):
    if len(argv) != 3:
        sys.exit('usage: loginkey.py <disc.iso> <out file>')
    key = from_iso(argv[1])
    if key is None:
        sys.exit('No DDR login key in %s. Use an Extreme 2, SuperNOVA or '
                 'SuperNOVA 2 disc image (.iso).' % argv[1])
    os.makedirs(os.path.dirname(os.path.abspath(argv[2])), exist_ok=True)
    with open(argv[2], 'wb') as f:
        f.write(key)
    print('wrote %s' % argv[2])


if __name__ == '__main__':
    main(sys.argv)
