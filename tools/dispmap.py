"""dispmap.py <file> <textoff> <vbase> <lo> <hi>
Parse `addiu $v0,$zero,IMM` + `beq $s2,$v0,TGT` compare chains into opcode->target."""
import sys, struct
from capstone import *
path=sys.argv[1]; foff=int(sys.argv[2],0); vbase=int(sys.argv[3],0)
lo=int(sys.argv[4],0); hi=int(sys.argv[5],0)
d=open(path,'rb').read()
md=Cs(CS_ARCH_MIPS, CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN); md.detail=True
insns={}
for va in range(lo,hi,4):
    f=va-vbase+foff
    g=list(md.disasm(d[f:f+4],va))
    insns[va]=g[0] if g else None
pend=None
out=[]
for va in range(lo,hi,4):
    i=insns.get(va)
    if not i: continue
    if i.mnemonic=='addiu' and i.op_str.startswith('$v0, $zero,'):
        pend=(int(i.op_str.split(',')[2],0), va)
    elif i.mnemonic in ('beq','bne') and i.op_str.startswith('$s2, $v0,'):
        tgt=int(i.op_str.split(',')[2],0)
        # the immediate may be in the delay slot of the *previous* branch
        cand=None
        if pend and pend[1]<va: cand=pend[0]
        if cand is None: continue
        out.append((cand,tgt,va))
        pend=None
for op,tgt,va in sorted(out):
    print("  0x%04x -> 0x%08x   (beq @0x%08x)"%(op,tgt,va))
