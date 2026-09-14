"""scandisp.py <file> <textoff> <vbase> <lo_disp> <hi_disp> [--store] [--load]

Every load/store whose 16-bit DISPLACEMENT falls in [lo,hi], whatever the base
register. Struct fields inside a scene object are reached as `lbu $v0,0x2344($s0)`
-- the offset is in the instruction, the base is a pointer the scanner cannot
resolve -- so this is the way to find a field's consumers when the base is not a
global. Noisy by construction: two structs with the same offset look alike. Read
the enclosing function before believing a hit.
"""
import sys, struct

path, foff, vbase = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0)
lo, hi = int(sys.argv[4], 0), int(sys.argv[5], 0)
want_store = '--store' in sys.argv
want_load = '--load' in sys.argv
if not want_store and not want_load:
    want_store = want_load = True

NAMES = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4',
         't5','t6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9',
         'k0','k1','gp','sp','fp','ra']
OPS = {0x20:('lb','L'), 0x21:('lh','L'), 0x23:('lw','L'), 0x24:('lbu','L'),
       0x25:('lhu','L'), 0x27:('lwu','L'), 0x37:('ld','L'), 0x1f:('sq','S'),
       0x28:('sb','S'), 0x29:('sh','S'), 0x2b:('sw','S'), 0x3f:('sd','S'),
       0x31:('lwc1','L'), 0x39:('swc1','S')}

d = open(path, 'rb').read()
for off in range(foff, len(d) - 3, 4):
    x = struct.unpack_from('<I', d, off)[0]
    op = x >> 26
    if op not in OPS:
        continue
    mnem, kind = OPS[op]
    if kind == 'S' and not want_store:
        continue
    if kind == 'L' and not want_load:
        continue
    imm = x & 0xffff
    if imm & 0x8000 or not (lo <= imm <= hi):
        continue
    print('%08x  %s  %-5s $%s, 0x%x($%s)'
          % (off - foff + vbase, kind, mnem, NAMES[(x >> 16) & 0x1f], imm,
             NAMES[(x >> 21) & 0x1f]))
