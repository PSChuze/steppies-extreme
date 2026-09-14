"""blockwriters.py -- who WRITES through a pointer held in a global?

scanfield.py finds loads of the global itself. That is not the same question:
a consumer loads the pointer into a register and then stores through it, often
after adding an index. This taints the loaded register, propagates the taint
through addu/addiu/move, and reports every store whose BASE is tainted.

    python tools/blockwriters.py 0x0104c0d0
"""
import struct, sys

LOADS  = {0x20:'lb',0x21:'lh',0x23:'lw',0x24:'lbu',0x25:'lhu',0x27:'lwu',0x37:'ld',
          0x31:'lwc1',0x35:'ldc1'}
STORES = {0x28:'sb',0x29:'sh',0x2b:'sw',0x3f:'sd',0x39:'swc1',0x3d:'sdc1'}
N = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5',
     't6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1',
     'gp','sp','fp','ra']

d = open('work/iso/x2/SLUS_211.74', 'rb').read()
FOFF, VB = 0x200, 0x100000
w = lambda va: struct.unpack_from('<I', d, va - VB + FOFF)[0]
target = int(sys.argv[1], 0)

# pass 1: every load of the global -> (va, dest reg)
sites, lui = [], {}
for off in range(FOFF, len(d) - 3, 4):
    va = off - FOFF + VB
    x = struct.unpack_from('<I', d, off)[0]
    op, rs, rt, imm = x >> 26, (x >> 21) & 0x1f, (x >> 16) & 0x1f, x & 0xffff
    if op == 0x0f:
        lui[rt] = ((imm << 16), va); continue
    if op in LOADS and rs in lui and lui[rs][0] is not None:
        simm = imm - 0x10000 if imm & 0x8000 else imm
        if ((lui[rs][0] + simm) & 0xffffffff) == target and va - lui[rs][1] <= 0x200:
            sites.append((va, rt))

# pass 2: taint-follow each site
hits = []
for va0, reg0 in sites:
    taint = {reg0}
    for k in range(1, 60):
        va = va0 + k * 4
        x = w(va)
        op, rs, rt, imm = x >> 26, (x >> 21) & 0x1f, (x >> 16) & 0x1f, x & 0xffff
        if op in STORES and rs in taint:
            simm = imm - 0x10000 if imm & 0x8000 else imm
            hits.append((va0, va, STORES[op], N[rs], simm, N[rt]))
            continue
        if op == 0x0f:                                      # lui rt -- kills taint
            taint.discard(rt); continue
        if op == 0 and (x & 0x3f) in (0x21, 0x2d):          # addu/daddu rd,rs,rt
            rd = (x >> 11) & 0x1f
            (taint.add if (rs in taint or rt in taint) else taint.discard)(rd)
        elif op in (0x09, 0x19):                            # addiu/daddiu rt,rs
            (taint.add if rs in taint else taint.discard)(rt)
        elif op in LOADS:
            taint.discard(rt)
        elif op == 3:                                       # jal clobbers temps
            taint -= {2,3,4,5,6,7,8,9,10,11,12,13,14,15,24,25}
for va0, va, m, base, disp, src in hits:
    print("  store @%08x  %-4s $%s, 0x%x($%s)      (ptr loaded @%08x)"
          % (va, m, src, disp & 0xffff, base, va0))
print("--- %d load sites, %d write through the pointer" % (len(sites), len(hits)))
