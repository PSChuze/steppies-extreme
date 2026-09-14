import struct, re, sys, subprocess
d=open('work/iso/x2/SLUS_211.74','rb').read()
FOFF,VBASE=0x200,0x100000
def v2f(v): return v-VBASE+FOFF
def w(va): return struct.unpack_from('<I',d,v2f(va))[0]
# 1. build function map from xrefall
out=subprocess.run([sys.executable,'tools/xrefall.py','work/iso/x2/SLUS_211.74','0x200','0x00100000',
                    'out/x2.strings.txt','^NetPrg'],capture_output=True,text=True).stdout
funcs=[]
for line in out.splitlines():
    m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+<- (.*)',line)
    if not m: continue
    refs=[int(x,16) for x in m.group(3).split(', ')]
    funcs.append((min(refs),max(refs),m.group(2)))
funcs.sort()
def owner(va):
    best=None
    for lo,hi,name in funcs:
        if va<=hi+0x40: 
            if best is None or lo<=va<=hi+0x40 or va<lo: best=name; break
    return best or "?"
# 2. scan RPC region for `lw rX,0x8d8(rY)` and nearby addiu imm
LO,HI=0x001d7000,0x001e6700
res={}
for va in range(LO,HI,4):
    x=w(va)
    if (x>>26)==0x23 and (x&0xffff)==0x8d8:   # lw rt, 0x8d8(rs)
        for k in range(-6,7):
            y=w(va+k*4)
            if (y>>26)==0x09 and ((y>>21)&0x1f)==0:   # addiu rt,$zero,imm
                imm=y&0xffff
                if 0x1000<=imm<0xf000:
                    res.setdefault(owner(va),set()).add(imm)
print("%-28s %s"%("RPC","response opcode(s)"))
for lo,hi,name in funcs:
    if name in res:
        print("%-28s %s"%(name, ", ".join("0x%04x"%o for o in sorted(res[name]))))
