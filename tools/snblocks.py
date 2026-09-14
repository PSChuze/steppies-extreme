#!/usr/bin/env python3
"""Group SuperNOVA's response parsers by the STATE BLOCK each one drives, and
map the server pushes onto the event flags the lobby overlay polls.

`tools/sndispmap.py` recovers a group from the in-flight request compare at
ctx+0x2364+0xc. That works for most of the protocol and misses the rest, and
the miss is expensive: the friends list (0x3082/0x3084/0x3086) keeps its state
in a SECOND block at ctx+0x2c64, so its parsers never touch ctx+0x2364, so the
tool called them pushes -- and answering 0x3080 with the `+1` guess FROZE the
client, because 0x3081 has no parser at all.

This is the independent method. Every multi-part group shares one state block:
the parsers write the block's cursor at +0x00, its flag word at +0x08 and its
record count nearby. So the block IS the group, whether or not anyone compares
the in-flight request. Registers are tracked symbolically (ctx+K / constant) so
that the `lui r,1 ; addu r,ctx,r ; sw rX,0x42xx(r)` form used for big
displacements resolves. Neither of the older scans can see those: a
displacement scan does not know the base, and scanconst.py cannot help because
the constant being materialised is 0x10000.

It reproduces the two groups whose membership was already known from the
in-flight compare -- 0x5030 -> (0x5031,0x5032,0x5033) on ctx+0x13cd0 and
0x5034 -> (0x5035,0x5036,0x5037) on ctx+0x13f40 -- which is the check that it
is reading the binary correctly.

usage: snblocks.py [elf] [netlby overlay]
"""
import collections
import contextlib
import importlib.util
import io
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'sndispmap', os.path.join(_HERE, 'sndispmap.py'))
sndispmap = importlib.util.module_from_spec(_spec)
with contextlib.redirect_stdout(io.StringIO()):
    _spec.loader.exec_module(sndispmap)

w32 = sndispmap.w32

# The push event flags. Each is one byte a parser sets to 1 and the lobby
# overlay reads and then clears. ctx+0x142f4 is GetStartStaus's; the run from
# 0x142fc to 0x14306 is the push block.
FLAG_LO, FLAG_HI = 0x142f4, 0x14306
STORE = {0x28: 'sb', 0x29: 'sh', 0x2b: 'sw', 0x3f: 'sd'}
LOAD = {0x20: 'lb', 0x24: 'lbu', 0x21: 'lh', 0x25: 'lhu', 0x23: 'lw',
        0x37: 'ld'}
# caller-saved registers: what the tracker must forget across a jal
CLOBBER = set([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25])


def ctx_accesses(pa):
    """Every ctx-relative store a parser makes, as (mnemonic, offset, value).

    $a0 holds the net context on entry. Each register is tracked as ('ctx', K)
    or ('imm', V) and anything else is forgotten, so this reports only the
    accesses it can prove.
    """
    reg = {4: ('ctx', 0)}
    out = []
    end = None
    for va in range(pa, pa + 0x400, 4):
        w = w32(va)
        if w is None:
            break
        if end is not None and va > end:
            break
        op = w >> 26
        rs, rt = (w >> 21) & 0x1f, (w >> 16) & 0x1f
        imm = w & 0xffff
        simm = imm - 0x10000 if imm >> 15 else imm
        if op == 0 and (w & 0x3f) == 8 and rs == 31:      # jr $ra
            end = va + 4
        if op == 0:
            fn, rd = w & 0x3f, (w >> 11) & 0x1f
            a, b = reg.get(rs), reg.get(rt)
            if fn in (0x21, 0x2d):                        # addu / daddu
                if a and a[0] == 'ctx' and b and b[0] == 'imm':
                    reg[rd] = ('ctx', a[1] + b[1])
                elif b and b[0] == 'ctx' and a and a[0] == 'imm':
                    reg[rd] = ('ctx', b[1] + a[1])
                elif a and a[0] == 'ctx' and rt == 0:
                    reg[rd] = a
                else:
                    reg.pop(rd, None)
            elif fn == 0x25 and rt == 0:                  # or rd,rs,$zero
                if rs in reg:
                    reg[rd] = reg[rs]
                else:
                    reg.pop(rd, None)
            else:
                reg.pop(rd, None)
            continue
        if op == 0x0f:                                    # lui
            reg[rt] = ('imm', imm << 16)
            continue
        if op in (9, 0x19, 0x0d):                         # addiu/daddiu/ori
            a = reg.get(rs)
            v = imm if op == 0x0d else simm
            if rs == 0:
                reg[rt] = ('imm', v)
            elif a and a[0] == 'ctx' and op != 0x0d:
                reg[rt] = ('ctx', a[1] + v)
            elif a and a[0] == 'imm':
                reg[rt] = ('imm', (a[1] | imm) if op == 0x0d else a[1] + v)
            else:
                reg.pop(rt, None)
            continue
        if op in STORE:
            b = reg.get(rs)
            if b and b[0] == 'ctx':
                src = reg.get(rt)
                if src and src[0] == 'imm':
                    val = src[1]
                elif rt == 0:
                    val = 0
                else:
                    val = None
                out.append((STORE[op], b[1] + simm, val))
            continue
        if op == 3:                                       # jal
            for r in list(reg):
                if r in CLOBBER:
                    reg.pop(r, None)
            continue
        if op in LOAD:
            reg.pop(rt, None)
    return out


def cluster(offsets, gap=0x40):
    """Split offsets into blocks. One state block's fields sit within a few
    words of each other; a parser that drives two blocks touches them
    thousands of bytes apart."""
    out, cur = [], []
    for o in sorted(offsets):
        if cur and o - cur[-1] > gap:
            out.append(cur)
            cur = []
        cur.append(o)
    if cur:
        out.append(cur)
    return out


def scan_flag_bytes(path, foff, vbase):
    """Every byte access to the flag block, by displacement.

    The code forms `ctx + 0x10000` and leaves the rest in the displacement, so
    the displacement is the discriminator -- the materialised constant is
    0x10000 and useless to scan for.

    This also backstops the symbolic pass on the ELF side. `ctx_accesses` walks
    straight through a function and so loses a register that is only set on the
    branch-taken path: 0x4411's `sb $v1, 0x42f4($v0)` at 0x0026f17c and
    0x4351's `sb $v1, 0x4300($v0)` at 0x0026f7b4 are both reached that way and
    both go unseen. A displacement scan cannot miss them -- it just cannot say
    which field belongs to which context on its own, which is what the
    symbolic pass is for.
    """
    d = open(path, 'rb').read()
    hits = collections.defaultdict(list)
    for off in range(foff, len(d) - 3, 4):
        x = struct.unpack_from('<I', d, off)[0]
        op = x >> 26
        mn = LOAD.get(op) or STORE.get(op)
        if mn not in ('lb', 'lbu', 'sb'):
            continue
        field = 0x10000 + (x & 0xffff)
        if not (FLAG_LO <= field <= FLAG_HI):
            continue
        # sb $zero is the read-and-CLEAR half of the handshake, not a set
        if mn == 'sb' and ((x >> 16) & 0x1f) == 0:
            continue
        hits[field].append((off - foff + vbase, mn))
    return hits


def owning_parser(va, starts):
    """The parser a store at `va` belongs to: the nearest start at or before
    it, provided the store is inside the window scan_parser would have read."""
    best = None
    for s in starts:
        if s <= va < s + 0x400 and (best is None or s > best):
            best = s
    return best


def main():
    elf = sys.argv[1] if len(sys.argv) > 1 else 'work/iso/sn/SLUS_213.77'
    lby = sys.argv[2] if len(sys.argv) > 2 else 'work/iso/sn/DATA04.BIN'
    if elf != sndispmap.PATH:
        print('note: sndispmap parsed %s; pass the same ELF to both'
              % sndispmap.PATH, file=sys.stderr)

    roles, blocks, setters = {}, collections.defaultdict(list), {}
    for opc, pa in sorted(sndispmap.found.items()):
        _reqs, kind, _reads = sndispmap.scan_parser(pa, opc)
        roles[opc] = kind
        acc = ctx_accesses(pa)
        for cl in cluster([o for mn, o, _v in acc if mn in ('sw', 'sd')]):
            blocks[min(cl)].append(opc)
        for mn, o, v in acc:
            if mn == 'sb' and FLAG_LO <= o <= FLAG_HI and v == 1:
                setters[o] = opc

    print('state block -> the parsers that drive it  (= the message GROUP)')
    print('=' * 78)
    for base in sorted(blocks):
        members = sorted(set(blocks[base]))
        print('  ctx+0x%05x : %s'
              % (base, ', '.join('0x%04x %s' % (o, roles[o]) for o in members)))

    # Backstop the symbolic setters with a displacement scan of the ELF, then
    # attribute each store to the parser that contains it.
    by_parser = {pa: opc for opc, pa in sndispmap.found.items()}
    for field, hits in scan_flag_bytes(elf, sndispmap.FO, sndispmap.VB).items():
        for va, mn in hits:
            if mn != 'sb' or field in setters:
                continue
            pa = owning_parser(va, by_parser)
            if pa is not None:
                setters[field] = by_parser[pa]

    print()
    print('push -> event flag -> where %s reads it' % os.path.basename(lby))
    print('=' * 78)
    readers = scan_flag_bytes(lby, 0, 0xa46000)
    for field in range(FLAG_LO, FLAG_HI + 1):
        if field not in setters and field not in readers:
            continue
        rd = [va for va, mn in readers.get(field, []) if mn in ('lb', 'lbu')]
        print('  ctx+0x%05x  set by %s  read at %s'
              % (field,
                 ('0x%04x' % setters[field]) if field in setters else '  --  ',
                 ', '.join('%08x' % v for v in rd) or 'NOTHING READS IT'))


if __name__ == '__main__':
    main()
