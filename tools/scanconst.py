"""scanconst.py <file> <textoff> <vbase> <value...>

Find every place a 32-bit CONSTANT is materialised. Big struct displacements
(ctx+0x2a390, ctx+0x2b90c) never appear as a load immediate -- they do not fit
in the 16-bit field -- so scanaddr.py, which reconstructs *absolute* addresses,
cannot see them. They are built with a register pair instead:

    lui   $at, 0x2 ; ori   $at, $at, 0xb90c      -> 0x0002b90c
    ori   $at, $zero, 0x9f00                     -> 0x00009f00
    addiu $at, $zero, 0x1234                     -> sign-extended

and then ADDED to the context pointer. So the way to find who touches a field
is to find who materialises its offset. Prints the VA of the second half of the
pair plus the two instructions, and (when the next instruction is an addu) the
register the sum lands in.
"""
import sys, struct

path, foff, vbase = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0)
targets = set(int(x, 0) & 0xffffffff for x in sys.argv[4:])
d = open(path, 'rb').read()

NAMES = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4',
         't5','t6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9',
         'k0','k1','gp','sp','fp','ra']

def w(off):
    return struct.unpack_from('<I', d, off)[0]

lui = {}
for off in range(foff, len(d) - 3, 4):
    va = off - foff + vbase
    x = w(off)
    op = x >> 26
    rs, rt, imm = (x >> 21) & 0x1f, (x >> 16) & 0x1f, x & 0xffff
    if op == 0x0f:                                   # lui rt, imm
        lui[rt] = (imm << 16, va)
        continue
    val = src = None
    if op == 0x0d and rs in lui and lui[rs][0] is not None:      # ori rt,rs,imm
        val = lui[rs][0] | imm
        src = 'lui $%s,0x%x @%08x' % (NAMES[rs], lui[rs][0] >> 16, lui[rs][1])
    elif op == 0x09 and rs in lui and lui[rs][0] is not None:    # addiu rt,rs,imm
        simm = imm - 0x10000 if imm & 0x8000 else imm
        val = (lui[rs][0] + simm) & 0xffffffff
        src = 'lui $%s,0x%x @%08x' % (NAMES[rs], lui[rs][0] >> 16, lui[rs][1])
    elif op in (0x0d, 0x09) and rs == 0:                         # ori/addiu rt,$zero
        val = imm if op == 0x0d else (imm - 0x10000 if imm & 0x8000 else imm)
        val &= 0xffffffff
        src = ''
    if op in (0x0d, 0x09):
        lui[rt] = (val, va) if val is not None else (None, va)
    if val is None or val not in targets:
        continue
    nxt = w(off + 4) if off + 4 < len(d) - 3 else 0
    tail = ''
    # addu rd, rs, rt  (special, funct 0x21) -- the pointer being formed
    if (nxt >> 26) == 0 and (nxt & 0x3f) in (0x21, 0x2d):
        tail = '  -> addu $%s = $%s + $%s' % (NAMES[(nxt >> 11) & 0x1f],
                                              NAMES[(nxt >> 21) & 0x1f],
                                              NAMES[(nxt >> 16) & 0x1f])
    print('%08x  0x%08x -> $%-4s  %-34s%s' % (va, val, NAMES[rt], src, tail))
