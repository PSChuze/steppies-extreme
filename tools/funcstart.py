import sys, struct
path=sys.argv[1]; foff=int(sys.argv[2],0); vbase=int(sys.argv[3],0)
d=open(path,'rb').read()
def word(va):
    f=va-vbase+foff
    return struct.unpack_from('<I',d,f)[0] if 0<=f<len(d)-3 else 0
for t in sys.argv[4:]:
    va=int(t,0); found=None
    for a in range(va, va-0x8000, -4):
        w=word(a)
        if (w>>26)==9 and ((w>>21)&0x1f)==29 and ((w>>16)&0x1f)==29 and (w&0x8000):
            found=a; break
    # also scan forward for jr $ra to get end
    end=None
    for a in range(va, va+0x8000, 4):
        if word(a)==0x03e00008: end=a+8; break
    print("0x%08x -> func start 0x%08x  end ~0x%08x"%(va, found or 0, end or 0))
