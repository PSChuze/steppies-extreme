#!/usr/bin/env python3
"""Build the Cheat Device PS2 code list from patches/patches.json.

The same edits the disc patch makes, applied at runtime instead, so an
UNPATCHED retail disc can be booted with Cheat Device on a FreeMcBoot console.

  python3 tools/mkcheats.py "DDR Extreme 2 (USA).iso" "DDR SuperNOVA (USA).iso"
  python3 tools/mkcheats.py --check "DDR SuperNOVA (USA).iso"    # verify only

The image is required and every byte is verified against it, exactly as
isopatch.py does.  An address written down wrong is silent here -- the engine
writes to it anyway -- so nothing is emitted that has not been read off a disc
first.

Three things this has to get right, and all three are checked:

  * the hook.  A 9-type enable code tells the engine where to install its
    per-frame jump and which opcode it should expect to find there.  The
    engine compares that word before patching anything, which is what keeps
    the codes off OpenPS2Loader and off the other game.
  * the overlay.  SuperNOVA's DNAS2 bypass lives at 0x00a46000, a slot that
    NINE modules share (PH1-PH9 of the boot ELF all map there).  An
    unconditional write would corrupt whichever one is resident, which is why
    a pnach cannot do this at all.  The write
    is gated on the resident module's own signature instead -- the very word
    the patch replaces -- so it lands on net_mas4 and on nothing else.
    check_overlay_unique() proves that signature is in no other module.
  * the strings.  The service-URL edits are not word-aligned, so they are
    re-cut into word writes across the whole table, emitting only the words
    that actually change.

Then simulate() runs the emitted lines against the files they target and
requires the result to be the patched disc, byte for byte; for a guarded cheat
it also requires that the codes write nothing to any other module in the slot,
and nothing more once the patch has landed.

See docs/cheats.md.
"""
import os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import isopatch as ip

OUT = os.path.join(HERE, os.pardir, 'patches', 'cheats', 'DDR-Online.txt')

# 9-type hook codes.  Both are the long-published enable codes for these two
# discs, and both land on the same libpad routine -- the opcode is identical
# because it is the same library, linked at a different address:
#
#   00118618  sd    $ra, 0x90($sp)      <- $ra already saved, so the engine's
#   0011861c  addiu $v0, $v0, -0x2c30      own `jal' is free to clobber it
#   00118620  addu  $a0, $a0, $v1       <- hook here; backed up and re-run
#   00118624  addu  $v0, $v0, $a0       <- delay slot, backed up and re-run
#
# Both are verified against the retail ELF below, and build() also checks that
# neither address holds this opcode in the other game.
HOOKS = {
    'SLUS-21174': (0x00118620, 0x00832021),
    'SLUS-21377': (0x001273B8, 0x00832021),
    # SuperNOVA 2 has no published enable code. The same libpad routine is
    # linked at 0x00128bxx: the thirteen `addu a0,a0,v1 ; addu v0,v0,a0`
    # sites line up one for one with SuperNOVA's at the same spacing, and
    # 0x00128c00 is the one behind `sd $ra, 0x90($sp)`, as 0x001273b8 is.
    'SLUS-21608': (0x00128C00, 0x00832021),
}

# A module loaded into a vaddr that more than one program header claims is
# sharing that slot with the others, and writes to it have to be conditional.
# That is worked out from the boot ELF rather than written down here.


def phdrs(f, base):
    """Every program header of the boot ELF, as (offset, vaddr, filesz).

    PH0 is the main program.  The rest are overlay slots: same file offset,
    no file content, and several of them at the SAME vaddr -- that is how the
    shared slot shows up, and it is where the count in the note comes from.
    """
    f.seek(base)
    hdr = f.read(0x34)
    if hdr[:4] != b'\x7fELF':
        sys.exit("boot file is not an ELF")
    phoff, = struct.unpack_from('<I', hdr, 0x1c)
    phentsize, phnum = struct.unpack_from('<HH', hdr, 0x2a)
    f.seek(base + phoff)
    raw = f.read(phentsize * phnum)
    out = []
    for i in range(phnum):
        _, off, va, _, filesz, _, _, _ = struct.unpack_from('<8I', raw,
                                                            i * phentsize)
        out.append((off, va, filesz))
    return out


def code(kind, addr, value):
    return '%s%07X %08X' % (kind, addr & 0x0FFFFFFF, value)


def boot_name(serial):
    """SLUS-21377 -> SLUS_213.77, the name in the image's root directory."""
    s = serial.replace('-', '_')
    return s[:8] + '.' + s[8:]


def check_overlay_unique(f, children, patched, at, sig):
    """No other module may carry the signature word at the same offset.

    Every DATAnn.BIN in the image is checked, not only the ones already known
    to share the slot: the guard is worth exactly as much as this claim.
    """
    clash, seen = [], 0
    for name, (base, size) in sorted(children.items()):
        if not (name.startswith('DATA') and name.endswith('.BIN')):
            continue
        if name == patched:
            continue
        seen += 1
        if at + 4 > size:
            continue
        f.seek(base + at)
        if struct.unpack('<I', f.read(4))[0] == sig:
            clash.append(name)
    if clash:
        sys.exit("guard is not unique: %08x at +%06x is also in %s.\n"
                 "Do NOT ship these codes; find another signature."
                 % (sig, at, ', '.join(clash)))
    return seen


def word_writes(manifest, serial, fname, f, base, load_va):
    """One file's manifest edits -> [(address, value)] word writes.

    'word' edits map straight across.  'cstr' edits do not: the strings are
    not word-aligned and neither start nor end on a word boundary, so the
    whole table is re-cut into words and only the changed ones are kept.
    """
    _, edits = ip.file_edits(manifest, serial, fname)
    out, loose = [], {}
    for at, exp, rep, label in edits:
        f.seek(base + at)
        got = f.read(len(exp))
        if got != exp:
            sys.exit("VERIFY FAILED at %s+%06x\n  have %r\n  want %r"
                     % (fname, at, got, exp))
        if len(exp) == 4 and len(rep) == 4:
            out.append((load_va + at, struct.unpack('<I', rep)[0]))
        else:
            for i, b in enumerate(rep):
                loose[at + i] = b

    if loose:
        lo, hi = min(loose) & ~3, (max(loose) + 4) & ~3
        f.seek(base + lo)
        orig = bytearray(f.read(hi - lo))
        new = bytearray(orig)
        for off, b in loose.items():
            new[off - lo] = b
        for i in range(0, hi - lo, 4):
            if orig[i:i + 4] != new[i:i + 4]:
                out.append((load_va + lo + i, struct.unpack_from('<I', new, i)[0]))
    return edits, out


def guard_lines(edits, writes):
    """Two D-type lines that let the writes through only for this module.

    D-type compares 16 bits at a time, so the 32-bit signature takes two, one
    nested inside the other:

      D<va+2> nn00 <sig high half>   execute the next nn lines if it matches
      D<va+0> nn00 <sig low half>    ... and the next nn of those if it does
      2<va+0> ...                    the writes

    A module that is not net_mas4 fails the first compare, the engine skips
    every line the count covers, and nothing is written.  Once the writes have
    landed the signature is gone -- it is the word the first write replaces --
    so the guard also stops the codes re-applying to already-patched memory,
    and lets them re-apply if the module is loaded again.
    """
    sig, = struct.unpack('<I', edits[0][1])
    base = writes[0][0]
    n = len(writes)
    return sig, [code('D', base + 2, ((n + 1) << 24) | (sig >> 16)),
                 code('D', base, (n << 24) | (sig & 0xFFFF))]


def run_codes(lines, base_va, mem):
    """Run emitted code lines against one loaded file.  Returns writes made.

    Only the types this tool emits, and enough of the engine's behaviour to be
    worth running: a D-type either falls through or skips the number of lines
    it names, and a 2-type writes a word.  That is the whole of it.
    """
    pairs = [(int(l[:8], 16), int(l[9:], 16)) for l in lines]
    i = wrote = 0
    while i < len(pairs):
        a, v = pairs[i]
        kind, addr = a >> 28, (a & 0x0FFFFFFF) - base_va
        if kind == 9:                                  # hook; not a write
            i += 1
        elif kind == 2:
            if 0 <= addr <= len(mem) - 4:
                struct.pack_into('<I', mem, addr, v)
                wrote += 1
            i += 1
        elif kind == 0xD:
            n, test, eight = v >> 24, (v >> 20) & 7, (v >> 16) & 1
            want = v & (0xFF if eight else 0xFFFF)
            if not (0 <= addr <= len(mem) - 2):
                return wrote                           # not loaded: no compare
            have = mem[addr] if eight else struct.unpack_from('<H', mem, addr)[0]
            if test != 0:
                sys.exit("simulate: only the equal test is emitted")
            i = i + 1 if have == want else i + 1 + n
        else:
            sys.exit("simulate: unexpected code type %X" % kind)
    return wrote


def simulate(f, children, fname, base, size, load_va, edits, body, guarded):
    """Run the emitted codes and check they produce the disc patch, exactly.

    Then the two things the guard is for: the codes must write nothing to any
    other module in the slot, and nothing to memory they have already patched.
    """
    f.seek(base)
    original = f.read(size)
    want = bytearray(original)
    for at, exp, rep, _ in edits:
        want[at:at + len(rep)] = rep

    mem = bytearray(original)
    run_codes(body, load_va, mem)
    if mem != want:
        bad = next(i for i in range(size) if mem[i] != want[i])
        sys.exit("simulate: %s+%06x is %02x, the disc patch makes it %02x"
                 % (fname, bad, mem[bad], want[bad]))

    if not guarded:
        # Unguarded codes keep writing the same words every frame, the way the
        # pnach does.  Nothing to check beyond the result being right.
        return 'reproduces the disc patch'

    again = run_codes(body, load_va, mem)
    if again:
        sys.exit("simulate: %s: the guard still lets %d write(s) through once "
                 "the patch has landed" % (fname, again))

    for other, (obase, osize) in sorted(children.items()):
        if not (other.startswith('DATA') and other.endswith('.BIN')):
            continue
        if other == fname:
            continue
        f.seek(obase)
        resident = bytearray(f.read(osize))
        if run_codes(body, load_va, resident):
            sys.exit("simulate: the codes write into %s, which shares the "
                     "slot.  Do NOT ship them." % other)
    return ('reproduces the disc patch; the guard closes after it, and lets '
            'nothing through to any other module')


def build(path, manifest):
    """One image -> (serial, title, [(name, lines, why)], [notes], [checks])."""
    cheats, notes, checks = [], [], []
    with open(path, 'rb') as f:
        children = ip.root_children(f)
        serial = ip.boot_serial(f, children)
        if serial not in manifest['games']:
            sys.exit("boot ELF says %s, which this project has no patches for"
                     % serial)
        game = manifest['games'][serial]
        boot = boot_name(serial)
        elf_base, _ = children[boot]
        phs = phdrs(f, elf_base)
        off0, va0, filesz = phs[0]

        def elf_word(va):
            f.seek(elf_base + va - va0 + off0)
            return struct.unpack('<I', f.read(4))[0]

        hook_va, hook_op = HOOKS[serial]
        got = elf_word(hook_va)
        if got != hook_op:
            sys.exit("hook %08x: this ELF has %08x, expected %08x -- wrong "
                     "release or a bad dump" % (hook_va, got, hook_op))
        for other, (ova, oop) in HOOKS.items():
            if other != serial and elf_word(ova) == oop:
                sys.exit("%s's hook opcode is also at %08x in %s; the enable "
                         "codes do not tell the two games apart"
                         % (other, ova, serial))
        cheats.append(('Enable Code (must be on)', [code('9', hook_va, hook_op)],
                       'Installs the code engine, and only on this disc.'))

        for fname, spec in game['files'].items():
            base, size = children[fname]
            if size != spec['size']:
                sys.exit("%s is %d bytes, expected %d -- wrong release or a "
                         "bad dump" % (fname, size, spec['size']))
            if fname == boot:
                load_va = va0 - off0
            else:
                load_va = int(spec['load_vaddr'], 16)

            edits, writes = word_writes(manifest, serial, fname, f, base, load_va)
            if fname == boot:
                for at, _, _, _ in edits:
                    if not (off0 <= at < off0 + filesz):
                        sys.exit("%s+%06x is outside PH0, so it is not simply "
                                 "resident in memory" % (fname, at))

            body, guarded = [], False
            if sum(1 for _, va, _ in phs[1:] if va == load_va) > 1:
                guarded = True
                at = edits[0][0]
                sig, body = guard_lines(edits, writes)
                seen = check_overlay_unique(f, children, fname, at, sig)
                notes.append('The two D lines are that test.  They compare '
                             'the halves of %08x, the word at +%06x that the '
                             'first write replaces, and let the %d writes '
                             'through only for the module that has it.  None '
                             'of the other %d modules on the disc does, which '
                             'mkcheats.py checks before emitting this.  Once '
                             'the writes land the signature is gone and they '
                             'go quiet; load %s again and they re-apply.'
                             % (sig, at, len(writes), seen,
                                spec.get('module', fname)))
            body += [code('2', a, v) for a, v in writes]
            checks.append('%-14s %s' % (fname, simulate(
                f, children, fname, base, size, load_va, edits, body, guarded)))

            name = ('DNAS bypass (required)' if 'DNAS' in spec['why']
                    else 'Service URLs -> this project\'s web server')
            cheats.append((name, body, spec['why']))

    return serial, game['title'], cheats, notes, checks


def render(games):
    out = [
        '// Dance Dance Revolution online: the disc patch as runtime codes.',
        '//',
        '// For Cheat Device PS2 on a FreeMcBoot console booting the ORIGINAL,',
        '// unpatched disc.  Same edits as tools/isopatch.py writes into an ISO;',
        '// you need one or the other, never both.',
        '//',
        '// Generated by tools/mkcheats.py from patches/patches.json, with every',
        '// byte verified against a retail image.  Do not hand-edit.',
        '//',
        '// Turn the Enable Code on for whichever game you are booting.  It is a',
        '// 9-type hook: the engine compares the opcode at that address before it',
        '// installs itself, so the codes cannot fire on the loader, and the two',
        '// games cannot fire on each other.',
        '//',
        '// Getting past DNAS is all these do.  The console still has to resolve',
        '// the konamionline.com names to your server.  See docs/cheats.md.',
        '//',
        '// Every address, opcode and byte below was read out of a retail image',
        '// and checked before it was written here.  A console boot with these',
        '// codes is the one thing that has not been done; docs/cheats.md says',
        '// what to look at if one of them misbehaves.',
        '',
    ]
    for serial, title, cheats, notes, checks in games:
        out.append('// ' + '=' * 72)
        out.append('"%s [%s]"' % (title, serial))
        out.append('')
        for name, body, why in cheats:
            for line in wrap(why):
                out.append('// ' + line)
            for note in (notes if name.startswith('DNAS') else []):
                out.append('//')
                for line in wrap(note):
                    out.append('// ' + line)
            out.append(name)
            out += body
            out.append('')
    return '\n'.join(out).rstrip() + '\n'


def wrap(text, width=74):
    line, out = '', []
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = (line + ' ' + word).strip()
    if line:
        out.append(line)
    return out


def main(argv):
    check = '--check' in argv
    args = [a for a in argv if not a.startswith('--')]
    if not args:
        sys.exit("usage: mkcheats.py [--check] <iso> [<iso> ...]")
    manifest = ip.load()
    games = [build(p, manifest) for p in args]
    for serial, title, cheats, notes, checks in games:
        print('%s  [%s]' % (title, serial))
        for name, body, why in cheats:
            print('  %-46s %2d code line(s)' % (name, len(body)))
        for line in checks:
            print('  %s' % line)
    text = render(games)
    if check:
        print('\n--check: verified, nothing written')
        return
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', newline='\n') as f:
        f.write(text)
    print('\nwrote %s  (%d lines)'
          % (os.path.normpath(OUT), len(text.splitlines())))


if __name__ == '__main__':
    main(sys.argv[1:])
