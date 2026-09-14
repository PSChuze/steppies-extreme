import struct, re, sys, subprocess
d=open('work/iso/x2/SLUS_211.74','rb').read()
FOFF,VB=0x200,0x100000
def w(off): return struct.unpack_from('<I',d,off)[0]
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
    prev=None
    for lo,hi,name in funcs:
        if va < lo:
            return prev or name
        prev=name
    return prev
res={}
for off in range(FOFF,len(d)-3,4):
    va=off-FOFF+VB
    if not (0x001d7000 <= va <= 0x001e6700): continue
    x=w(off)
    if (x>>26)==0x09 and ((x>>21)&0x1f)==0:      # addiu rt,$zero,imm
        imm=x&0xffff
        if 0x2000<=imm<=0x6fff:
            res.setdefault(owner(va),set()).add(imm)
print("%-28s %s"%("RPC","all 0x2000-0x6fff immediates in its body"))
for lo,hi,name in funcs:
    if name in res:
        print("%-28s %s"%(name, " ".join("0x%04x"%o for o in sorted(res[name]))))
