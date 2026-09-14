"""scanaddr.py <file> <textoff> <vbase> <lo> <hi> <target_vaddr> [--gp 0xNNNN]
Find every load/store whose effective address == target, via lui+imm or $gp+imm.
Prints  VA  L/S  mnemonic  operands   (and the constructing lui)."""
import sys, struct
from capstone import *

path=sys.argv[1]; foff=int(sys.argv[2],0); vbase=int(sys.argv[3],0)
lo=int(sys.argv[4],0); hi=int(sys.argv[5],0); target=int(sys.argv[6],0)
gp=None
if '--gp' in sys.argv: gp=int(sys.argv[sys.argv.index('--gp')+1],0)

d=open(path,'rb').read()
md=Cs(CS_ARCH_MIPS, CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN)
md.detail=True

LOADS ={'lw','lh','lhu','lb','lbu','lwu','ld','lwl','lwr','ldl','ldr','lwc1','ldc1'}
STORES={'sw','sh','sb','sd','swl','swr','sdl','sdr','swc1','sdc1'}

def v2f(v): return v-vbase+foff

# pass: linear sweep tracking last lui per reg (reset on function prologue heuristics off; keep simple window)
last={}   # reg -> (value, va)
hits=[]
for va in range(lo,hi,4):
    f=v2f(va)
    if f+4>len(d): break
    w=struct.unpack_from('<I',d,f)[0]
    op=w>>26
    if op==0x0f:   # lui
        rt=(w>>16)&0x1f; last[rt]=((w&0xffff)<<16, va); continue
    g=list(md.disasm(d[f:f+4],va))
    if not g: continue
    i=g[0]; m=i.mnemonic
    if m not in LOADS and m not in STORES: continue
    # operands: base reg + imm
    base=None; imm=None
    for o in i.operands:
        if o.type==CS_OP_MEM:
            base=o.mem.base; imm=o.mem.disp
    if base is None: continue
    bn=i.reg_name(base)
    addr=None; src=None
    if bn=='gp' and gp is not None:
        addr=(gp+imm)&0xffffffff; src='gp'
    else:
        rn=base
        # capstone reg id -> mips reg number
        num=None
        try: num=int(bn[1:]) if bn[1:].isdigit() else None
        except: num=None
        # map by name
        NAMES={'zero':0,'at':1,'v0':2,'v1':3,'a0':4,'a1':5,'a2':6,'a3':7,
               't0':8,'t1':9,'t2':10,'t3':11,'t4':12,'t5':13,'t6':14,'t7':15,
               's0':16,'s1':17,'s2':18,'s3':19,'s4':20,'s5':21,'s6':22,'s7':23,
               't8':24,'t9':25,'k0':26,'k1':27,'gp':28,'sp':29,'fp':30,'s8':30,'ra':31}
        num=NAMES.get(bn,num)
        if num in last:
            val,lva=last[num]
            if va-lva<=0x100:
                addr=(val+imm)&0xffffffff; src='lui@%08x'%lva
    if addr==target:
        hits.append((va,'S' if m in STORES else 'L',m,i.op_str,src))

for va,ls,m,ops,src in hits:
    print("%08x  %s  %-6s %-28s %s"%(va,ls,m,ops,src))
print("--- %d hits (%d store, %d load)"%(len(hits),
      sum(1 for h in hits if h[1]=='S'), sum(1 for h in hits if h[1]=='L')))
