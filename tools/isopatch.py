#!/usr/bin/env python3
"""Apply this project's disc patches to your own copy of the game.

Reads patches/patches.json, works out which game the image is by its boot ELF,
and applies every edit for that game.  Handles both titles:

  Extreme 2  (SLUS-21174)  DNAS bypass in SLUS_211.74
  SuperNOVA  (SLUS-21377)  DNAS2 bypass in DATA03.BIN, service URLs in SLUS_213.77

Every edit is SIZE-NEUTRAL, so each file's sectors are overwritten in place and
the ISO9660 layout -- every LBA the game hardcodes -- is left untouched.  A full
rebuild would not guarantee that.

Every original byte is verified before anything is written.  Standard library
only; nothing to install.  Never patches in place.

  python3 tools/isopatch.py "DDR SuperNOVA (USA).iso" "DDR SuperNOVA (USA) [ONLINE].iso"
  python3 tools/isopatch.py --dry-run "DDR Extreme 2 (USA).iso"

See docs/patching.md.  Most players should use the .xdelta from Releases
instead; this is here so that no download and no patcher are ever required.
"""
import hashlib, json, os, shutil, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, os.pardir, 'patches', 'patches.json')
SECTOR = 2048
SEP = chr(92)   # backslash; SYSTEM.CNF reads  BOOT2 = cdrom0:<SEP>SLUS_213.77;1

USAGE = ("usage: isopatch.py [--dry-run] <src.iso> [dst.iso]")


# ---------------------------------------------------------------- ISO9660 ---
def root_children(f):
    """Map every name in the root directory to (byte offset, length)."""
    f.seek(16 * SECTOR)
    pvd = f.read(SECTOR)
    if pvd[1:6] != b'CD001':
        sys.exit("no CD001 signature at byte %d -- not a 2048-byte-sector ISO.\n"
                 "Raw 2352-byte dumps (.bin) are not supported; use a .iso."
                 % (16 * SECTOR))
    rec = pvd[156:156 + 34]                       # root directory record
    f.seek(struct.unpack_from('<I', rec, 2)[0] * SECTOR)
    data = f.read(struct.unpack_from('<I', rec, 10)[0])

    out, pos = {}, 0
    while pos < len(data):
        rlen = data[pos]
        if rlen == 0:                             # padding to the next sector
            pos = (pos // SECTOR + 1) * SECTOR
            continue
        r = data[pos:pos + rlen]
        name = r[33:33 + r[32]].decode('latin-1').split(';')[0]
        out[name] = (struct.unpack_from('<I', r, 2)[0] * SECTOR,
                     struct.unpack_from('<I', r, 10)[0])
        pos += rlen
    return out


def boot_serial(f, children):
    """SLUS_213.77 -> 'SLUS-21377', read from SYSTEM.CNF's BOOT2 line."""
    if 'SYSTEM.CNF' not in children:
        sys.exit("no SYSTEM.CNF in the root directory -- is this a PS2 disc image?")
    off, size = children['SYSTEM.CNF']
    f.seek(off)
    for line in f.read(size).decode('latin-1').splitlines():
        if line.upper().startswith('BOOT2'):
            name = line.split('=', 1)[1].strip().split(SEP)[-1].split(';')[0]
            return name.replace('_', '-').replace('.', '', 1).strip()
    sys.exit("SYSTEM.CNF has no BOOT2 line")


# ---------------------------------------------------------------- manifest --
def load():
    with open(MANIFEST, 'rb') as f:
        return json.load(f)


def file_edits(manifest, serial, fname):
    """Edits for one named file, as (offset_in_file, expect, replace, label).

    Offsets are relative to the file itself, so this serves both the in-image
    patcher below and the loose-file tools (snpatch.py, elfpatch.py).  That is
    the point: patches/patches.json is the only place these bytes are written
    down, and nothing can drift out of step with it.
    """
    spec = manifest['games'][serial]['files'][fname]
    port = manifest['web_port']
    out = []
    for e in spec['edits']:
        at = int(e['at'], 16)
        if e['kind'] == 'word':
            exp = struct.pack('<I', int(e['expect'], 16))
            rep = struct.pack('<I', int(e['replace'], 16))
            label = "%s+%06x  %s -> %s" % (fname, at, e['was'], e['now'])
        elif e['kind'] == 'cstr':
            exp = e['expect'].encode() + b'\x00'
            txt = e['replace'].format(web_port=port).encode()
            if len(txt) + 1 > len(exp):
                sys.exit("%s+%06x: replacement needs %d bytes, slot is %d"
                         % (fname, at, len(txt) + 1, len(exp)))
            rep = txt + b'\x00' * (len(exp) - len(txt))
            label = "%s+%06x  %2d/%2d bytes  %s" % (fname, at, len(txt) + 1,
                                                    len(exp), txt.decode())
        else:
            sys.exit("unknown edit kind %r" % e['kind'])
        out.append((at, exp, rep, label))
    return spec, out


def verify(f, plan):
    """Check every expected byte. Returns how many bytes an apply would change."""
    changed = 0
    for off, exp, rep, label in plan:
        f.seek(off)
        got = f.read(len(exp))
        if got != exp:
            sys.exit("VERIFY FAILED at 0x%x (%s)\n  have %r\n  want %r"
                     % (off, label.split()[0], got, exp))
        changed += sum(a != b for a, b in zip(exp, rep))
    return changed


def resolve(manifest, serial, children):
    """Flatten the manifest into [(abs_offset, expect, replace, label)]."""
    game = manifest['games'][serial]
    plan = []
    for fname in game['files']:
        if fname not in children:
            sys.exit("%s is not in the image's root directory" % fname)
        base, length = children[fname]
        spec, edits = file_edits(manifest, serial, fname)
        if length != spec['size']:
            sys.exit("%s is %d bytes, expected %d -- wrong release or a bad dump"
                     % (fname, length, spec['size']))
        plan += [(base + at, e, r, l) for at, e, r, l in edits]
    return game, plan


def patch_loose(serial, fname, src, dst):
    """Apply one file's edits to that file on its own, not inside an image.

    Used by snpatch.py and elfpatch.py.
    """
    if os.path.abspath(src) == os.path.abspath(dst):
        sys.exit("refusing to patch in place; give a separate output path")
    spec, plan = file_edits(load(), serial, fname)
    size = os.path.getsize(src)
    if size != spec['size']:
        sys.exit("%s is %d bytes, expected %d -- wrong release or a bad dump"
                 % (src, size, spec['size']))
    with open(src, 'rb') as f:
        changed = verify(f, plan)
    print("verified %d edits against the source; %d bytes will change\n"
          % (len(plan), changed))
    shutil.copyfile(src, dst)
    with open(dst, 'r+b') as f:
        for off, _, rep, label in plan:
            f.seek(off)
            f.write(rep)
            print("  %s" % label)
    print("\nwrote %s" % dst)


def sha1(path):
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 22), b''):
            h.update(chunk)
    return h.hexdigest()


# -------------------------------------------------------------------- main --
def main(argv, quiet=False):
    dry = '--dry-run' in argv
    args = [a for a in argv if not a.startswith('--')]
    if not (1 <= len(args) <= 2) or (not dry and len(args) != 2):
        sys.exit(USAGE)
    src = args[0]
    dst = args[1] if len(args) == 2 else None
    if dst and os.path.abspath(src) == os.path.abspath(dst):
        sys.exit("refusing to patch in place; give a separate output path")

    manifest = load()
    with open(src, 'rb') as f:
        children = root_children(f)
        serial = boot_serial(f, children)
        if serial not in manifest['games']:
            sys.exit("boot ELF says %s, which this project has no patches for.\n"
                     "Known: %s" % (serial, ', '.join(sorted(manifest['games']))))
        game, plan = resolve(manifest, serial, children)

        print("%s  [%s]" % (game['title'], serial))
        size = os.path.getsize(src)
        if size != game['source']['size']:
            print("  ! image is %d bytes, the reference dump is %d -- continuing,\n"
                  "    every edit is still verified byte-for-byte"
                  % (size, game['source']['size']))

        # ---- verify every original byte against the SOURCE, before any write --
        changed = verify(f, plan)
        print("  verified %d edits against the source; %d bytes will change\n"
              % (len(plan), changed))

    for _, _, _, label in plan:
        print("  %s" % label)

    if dry:
        print("\ndry run -- nothing written")
        return

    print("\ncopying %s -> %s ..." % (src, dst))
    shutil.copyfile(src, dst)
    with open(dst, 'r+b') as f:
        for off, _, rep, _ in plan:
            f.seek(off)
            f.write(rep)
        f.flush()
        os.fsync(f.fileno())
    print("wrote %s" % dst)
    if not quiet:
        print("  sha1 %s" % sha1(dst))


if __name__ == '__main__':
    main(sys.argv[1:])
