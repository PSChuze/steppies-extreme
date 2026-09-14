#!/usr/bin/env python3
"""Build the release .xdelta patches from a clean disc image.

This is the maintainer's tool, not the player's.  Players never run it: they
download the .xdelta and apply it to their own dump with xdelta3, DeltaPatcher
or any other VCDIFF patcher, and need no Python at all.

  python3 tools/mkpatch.py "DDR SuperNOVA (USA).iso"
  python3 tools/mkpatch.py "DDR Extreme 2 (USA).iso" -o patches/dist

For each image it patches a temporary copy via isopatch, encodes the delta,
then decodes that delta back and checks the result hashes to the same value.
A patch that has not been round-tripped is not published.

The source dump must match the sha1 recorded in patches/patches.json.  An
.xdelta carries a checksum of its source, so a player who starts from a
different dump gets a clean refusal rather than a broken disc.

Requires xdelta3 on PATH (scoop install xdelta / apt install xdelta3 /
brew install xdelta).
"""
import json, os, shutil, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isopatch

OUT_DEFAULT = os.path.join(isopatch.HERE, os.pardir, 'patches', 'dist')


def sha1(path, label=""):
    d = isopatch.sha1(path)
    if label:
        print("  sha1 %s  %s" % (d, label))
    return d


def slug(title):
    keep = "".join(c if c.isalnum() else " " for c in title)
    return "-".join(keep.split())


def main(argv):
    args = [a for a in argv if not a.startswith('-')]
    if not args:
        sys.exit("usage: mkpatch.py <clean.iso> [-o outdir] [--no-verify]")
    src = args[0]
    outdir = args[args.index('-o') + 1] if '-o' in argv else OUT_DEFAULT
    verify = '--no-verify' not in argv

    if shutil.which('xdelta3') is None:
        sys.exit("xdelta3 is not on PATH.\n"
                 "  scoop install xdelta | apt install xdelta3 | brew install xdelta")

    with open(isopatch.MANIFEST, 'rb') as f:
        manifest = json.load(f)
    with open(src, 'rb') as f:
        children = isopatch.root_children(f)
        serial = isopatch.boot_serial(f, children)
        if serial not in manifest['games']:
            sys.exit("no patches for %s" % serial)
        game, _ = isopatch.resolve(manifest, serial, children)

    print("%s  [%s]\n" % (game['title'], serial))
    print("source: %s" % src)
    got = sha1(src, "source dump")
    want = game['source']['sha1']
    if got != want:
        sys.exit("\nSOURCE MISMATCH -- refusing to build a patch nobody can apply.\n"
                 "  this dump  %s\n  manifest   %s\n"
                 "The published patch must be built from the reference dump."
                 % (got, want))
    print("  matches the manifest\n")

    os.makedirs(outdir, exist_ok=True)
    stem = "%s-online" % slug(game['title'])
    xd = os.path.join(outdir, stem + '.xdelta')

    tmpdir = tempfile.mkdtemp(prefix='mkpatch-', dir=outdir)
    try:
        patched = os.path.join(tmpdir, 'patched.iso')
        print("applying patches ...")
        isopatch.main([src, patched], quiet=True)
        target = sha1(patched, "patched image")

        print("\nencoding %s ..." % xd)
        subprocess.check_call(['xdelta3', '-e', '-9', '-f', '-s', src, patched, xd])
        print("  %d bytes" % os.path.getsize(xd))

        if verify:
            print("\nround-tripping the patch ...")
            back = os.path.join(tmpdir, 'roundtrip.iso')
            subprocess.check_call(['xdelta3', '-d', '-f', '-s', src, xd, back])
            if sha1(back, "decoded result") != target:
                sys.exit("ROUND TRIP FAILED -- the patch does not reproduce the image")
            print("  matches the patched image")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    meta = {
        'game': game['title'], 'serial': serial,
        'source_sha1': want, 'source_size': game['source']['size'],
        'patched_sha1': target,
        'patch': os.path.basename(xd), 'patch_sha1': sha1(xd),
    }
    with open(os.path.join(outdir, stem + '.json'), 'w') as f:
        json.dump(meta, f, indent=2)
        f.write("\n")

    print("\n%s\n  apply with: xdelta3 -d -s \"<your dump>.iso\" %s \"<output>.iso\""
          % (xd, os.path.basename(xd)))


if __name__ == '__main__':
    main(sys.argv[1:])
