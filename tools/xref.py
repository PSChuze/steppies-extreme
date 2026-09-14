import sys, struct
# xref.py <elf> <phoff_delta_off> <vaddr_base> <target_vaddr...>
path=sys.argv[1]; foff=int(sys.argv[2],0); vbase=int(sys.argv[3],0)
targets=[int(x,0) for x in sys.argv[4:]]
d=open(path,'rb').read()
text_off=foff
def v2f(v): return v - vbase + text_off
def f2v(f): return f - text_off + vbase
n=len(d)
words=[]
# build list of lui and addiu
lui={}   # index -> (rt, imm)
for off in range(text_off, n-3, 4):
    w=struct.unpack_from('<I',d,off)[0]
    op=w>>26
    if op==0x0f:  # lui
        lui[off]=((w>>16)&0x1f, w&0xffff)
    elif op==0x09: # addiu
        rs=(w>>21)&0x1f; rt=(w>>16)&0x1f; imm=w&0xffff
        # look back up to 64 instrs for matching lui rs
        for back in range(off-4, max(text_off, off-256)-1, -4):
            l=lui.get(back)
            if l and l[0]==rs:
                simm = imm-0x10000 if imm & 0x8000 else imm
                addr=((l[1]<<16)+simm) & 0xffffffff
                for t in targets:
                    if addr==t:
                        print("xref to 0x%08x  at vaddr 0x%08x (lui@0x%08x)" % (t, f2v(off), f2v(back)))
                break
