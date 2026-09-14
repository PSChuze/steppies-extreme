#!/usr/bin/env python3
"""Map SuperNOVA's receive dispatches: opcode -> parser -> request -> body shape.

SuperNOVA has no `NetPrg*` name table, so the Extreme 2 trick of recovering the
RPC map from debug strings does not work. But every response parser validates
TWO things before it does anything:

    lw   $v1, ($msg)          ; its OWN opcode
    beq  ...
    lw   $v1, 0xc($ctx+0x2364); the opcode of the REQUEST still in flight
    beq  ...

so the request/response grouping is readable straight out of the binary. This
walks the `li rX,OP ; beq $sN,rX,target` compare chains, follows each target to
its `jal parser`, and reports for every parser:

  * the request opcode it answers (the compared value that is not its own)
  * BEGIN / DATA / END, from the flag word it ORs into ctx+0x2364+8
        |= 2   -> BEGIN      |= 0xe  -> END       neither -> DATA
  * the body shape, as the ordered list of field-reader calls

Written after five consecutive "client hangs on an unknown opcode" round trips,
each of which was the same bug: a multi-part reply answered with one guessed
message. Sweeping the whole table offline is cheaper than discovering them one
hang at a time.

usage: sndispmap.py [elf]
"""
import struct, sys, collections
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_LITTLE_ENDIAN

PATH = sys.argv[1] if len(sys.argv) > 1 else 'work/iso/sn/SLUS_213.77'
FO, VB = 0x280, 0x100000
d = open(PATH, 'rb').read()
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN)

# The field codec, 0x00279a60-0x0027a300. **Several of these are duplicated**:
# the compiler emitted two identical copies of the u16 reader and two of the
# u8 reader, and a table that knows only one copy of each silently drops every
# field read through the other -- which makes the reported body SHORT, and a
# short body is the failure this whole tool exists to prevent.
#
#   0x279d30 == 0x279d80  byte-identical, and BOTH are big-endian:
#                         lb hi@+0x40 ; lbu lo@+0x41 ; sll 8 ; or
#                         The old table called them 'u16' and 'u16b' as though
#                         they differed. They do not. There is no little-endian
#                         u16 reader in the codec at all.
#   0x279dd0 == 0x279e10  byte-identical u8. Only the second was listed, so
#                         every field read by the first was invisible.
#
# Verified 2026-09-13 by fingerprinting every function in the codec region that
# opens by loading the cursor at msg+0x454; those four are the only duplicates.
READERS = {
    0x279c70: 'u32', 0x279b90: 's32', 0x279b10: 'str',
    0x279d30: 'u16', 0x279d80: 'u16',        # same function, both big-endian
    0x279dd0: 'u8', 0x279e10: 'u8',          # same function
    0x279a90: 'cstr', 0x279a60: 'more?',
    0x271530: 'STATUS(u32)',
}
SIZE = {'u32': 4, 's32': 4, 'u16': 2, 'u16b': 2, 'u8': 1, 'STATUS(u32)': 4}


def w32(va):
    o = va - VB + FO
    return struct.unpack_from('<I', d, o)[0] if 0 <= o < len(d) - 3 else None


def dis(va):
    o = va - VB + FO
    g = list(md.disasm(d[o:o + 4], va))
    return (g[0].mnemonic, g[0].op_str) if g else ('.word', '')


def is_op(v):
    return 0x0003 <= v <= 0x8fff


def scan_parser(pa, own):
    """Return (request_opcodes, kind, body-shape) for the parser at `pa`.

    The REQUEST is not merely "the other opcode constant in the function" -- that
    picks up loop bounds and unrelated literals. It is specifically the value
    compared against the in-flight request field, so look for

        lw   rX, 0xc(rY)      ; ctx+0x2364 + 0xc
        addiu/ori rZ, $zero, REQ
        beq  rX, rZ, body

    and take the opcode immediate that follows that load.

    **A parser can accept MORE THAN ONE request.** 0x0026c1b0 (0x4522) compares
    the in-flight field against BOTH 0x4520 and 0x4521 and runs the same body
    for either; 0x4525, 0x4528 and 0x452b do the same for their own pairs.
    Taking the first match -- which this did until 2026-09-13 -- reported only
    0x4520 and left 0x4521 looking unanswered, when the client is waiting for
    exactly the same reply. Collect every compare, and require the branch to
    test the register the `lw` actually loaded: without that check a nearby
    `addiu rD,$zero,imm` feeding an unrelated branch is read as a request
    (0x0044 was, out of the 0x4222 parser).
    """
    flags, reads = [], []
    reqs = []
    infl_reg = infl_at = None
    a2 = None                                 # last immediate loaded into $a2
    end = None
    for va in range(pa, pa + 0x400, 4):
        w = w32(va)
        if w is None:
            break
        op = w >> 26
        # STOP at the function's own `jr $ra` (+ its delay slot). A fixed window
        # overruns short parsers into the next function and invents fields --
        # that is what made 0x8003's END look like it had a record loop.
        if end is not None and va > end:
            break
        if op == 0 and (w & 0x3f) == 8 and ((w >> 21) & 0x1f) == 31:
            end = va + 4
        # lw rX, 0xc(rY) -- the in-flight request field at ctx+0x2364+0xc
        if op == 0x23 and (w & 0xffff) == 0x0c:
            infl_reg, infl_at = (w >> 16) & 0x1f, va
        if op in (9, 0x0d) and ((w >> 21) & 0x1f) == 0:
            v = w & 0xffff
            rd = (w >> 16) & 0x1f
            if rd == 6:                       # $a2 = the length arg for str
                a2 = v
            # The request compares sit in a short chain after the load. Each is
            # an immediate followed by a branch testing it against the loaded
            # register, and BOTH halves have to match: keying on the immediate
            # alone picks up loop bounds that merely look like opcodes.
            if (infl_reg is not None and va - infl_at <= 0x40
                    and is_op(v) and v != own and v not in reqs):
                nxt = w32(va + 4)
                if nxt is not None and (nxt >> 26) in (4, 5, 0x14, 0x15):
                    brs, brt = (nxt >> 21) & 0x1f, (nxt >> 16) & 0x1f
                    if infl_reg in (brs, brt) and rd in (brs, brt):
                        reqs.append(v)
        if op == 0x0d and (w & 0xffff) in (2, 0xe):
            flags.append(w & 0xffff)
        if op == 3:                           # jal
            t = ((va + 4) & 0xf0000000) | ((w & 0x03ffffff) << 2)
            if t in READERS:
                nm = READERS[t]
                if nm == 'str':
                    # MIPS: the length argument is very often in the CALL'S
                    # DELAY SLOT, i.e. the instruction AFTER the jal textually
                    # but executed before it. Reading only backwards misses it
                    # and reports every string as length 0 or unknown.
                    ds = w32(va + 4)
                    n = a2
                    if ds is not None and (ds >> 26) == 9 and ((ds >> 16) & 0x1f) == 6:
                        n = ds & 0xffff
                    nm = 'str[%s]' % (n if n is not None else '?')
                reads.append(nm)
    kind = 'BEGIN' if 2 in flags else ('END' if 0xe in flags else 'DATA')
    return reqs, kind, reads


def body_bytes(reads):
    n = 0
    for r in reads:
        if r in SIZE:
            n += SIZE[r]
        elif r.startswith('str['):
            inner = r[4:-1]
            if not inner.isdigit():
                return None
            n += int(inner)
        else:
            return None                       # variable / looping
    return n


# ---- walk every compare chain ------------------------------------------------
found = {}
# The three receive dispatches all live in one small region; scanning the whole
# ELF matches unrelated compare chains (menu ids, error tables) and produces
# noise. Parsers likewise all sit in the network block.
CHAIN_LO, CHAIN_HI = 0x00271700, 0x00273500
PARSER_LO, PARSER_HI = 0x00269000, 0x00274000

for o in range((CHAIN_LO - VB + FO), (CHAIN_HI - VB + FO), 4):
    va = o - FO + VB
    w = w32(va)
    if w is None or (w >> 26) not in (9, 0x0d) or ((w >> 21) & 0x1f) != 0:
        continue
    opc = w & 0xffff
    if not is_op(opc):
        continue
    m, ops = dis(va + 4)
    if m != 'beq':
        continue
    try:
        tgt = int(ops.split(',')[-1].strip(), 0)
    except ValueError:
        continue
    parser = None
    for k in range(0, 16, 4):
        mm, oo = dis(tgt + k)
        if mm == 'jal':
            parser = int(oo, 0)
            break
    if parser and PARSER_LO <= parser < PARSER_HI:
        found.setdefault(opc, parser)

groups = collections.defaultdict(list)
solo = []
for opc, pa in sorted(found.items()):
    reqs, kind, reads = scan_parser(pa, opc)
    n = body_bytes(reads)
    rec = (opc, pa, kind, reads, n)
    if reqs:
        for req in reqs:                      # one parser can answer several
            groups[req].append(rec)
    else:
        solo.append(rec)

order = {'BEGIN': 0, 'DATA': 1, 'END': 2}


# `found`, `groups` and `solo` stay at module level: tools/snblocks.py imports
# this to reuse the chain walk rather than reimplementing it.
def main():
    print('request -> responses (TERMINATOR LAST), with body shape')
    print('=' * 78)
    for req in sorted(groups):
        rs = sorted(groups[req], key=lambda r: (order[r[2]], r[0]))
        seq = ', '.join('0x%04x' % r[0] for r in rs)
        print('  0x%04x: (%s)' % (req, seq))
        for opc, pa, kind, reads, n in rs:
            print('      0x%04x %-5s parser %08x  %-3s  %s'
                  % (opc, kind, pa,
                     ('%dB' % n) if n is not None else 'var',
                     ', '.join(reads) or '-'))
    print()
    print('parsers with no in-flight request check (pushes / unsolicited): %s'
          % ', '.join('0x%04x' % r[0] for r in solo))
    print()
    print('Opcodes listed as pushes may still belong to a group this cannot')
    print('see: run tools/snblocks.py, which groups by state block instead.')


if __name__ == '__main__':
    main()
