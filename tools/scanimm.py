"""scanimm.py <file> <textoff> <vbase> <lo> <hi> <immlo> <immhi>
Find instructions whose 16-bit immediate falls in [immlo,immhi]."""
import sys, struct
from capstone import *
path=sys.argv[1]; foff=int(sys.argv[2],0); vbase=int(sys.argv[3],0)
lo=int(sys.argv[4],0); hi=int(sys.argv[5],0)
ilo=int(sys.argv[6],0); ihi=int(sys.argv[7],0)
d=open(path,'rb').read()
md=Cs(CS_ARCH_MIPS, CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN)
for va in range(lo,hi,4):
    f=va-vbase+foff
    if f+4>len(d): break
    w=struct.unpack_from('<I',d,f)[0]
    imm=w&0xffff
    if not (ilo<=imm<=ihi): continue
    op=w>>26
    if op in (0x0f,0x02,0x03): continue   # lui / j / jal
    g=list(md.disasm(d[f:f+4],va))
    if g: print("%08x  %-8s %s"%(va,g[0].mnemonic,g[0].op_str))
