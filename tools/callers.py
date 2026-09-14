"""callers.py <file> <textoff> <vbase> <lo> <hi> <target...>
Find every `jal target`. Also reports the enclosing function start (nearest
preceding `addiu $sp,$sp,-N` that follows a `jr $ra` + delay slot)."""
import sys, struct
path=sys.argv[1]; foff=int(sys.argv[2],0); vbase=int(sys.argv[3],0)
lo=int(sys.argv[4],0); hi=int(sys.argv[5],0)
targets=set(int(x,0) for x in sys.argv[6:])
d=open(path,'rb').read()
def v2f(v): return v-vbase+foff
def word(va):
    f=v2f(va)
    return struct.unpack_from('<I',d,f)[0] if 0<=f<len(d)-3 else 0

def is_prologue(va):
    w=word(va)
    # addiu $sp,$sp,-N   : op=9 rs=29 rt=29 imm negative
    return (w>>26)==9 and ((w>>21)&0x1f)==29 and ((w>>16)&0x1f)==29 and (w&0x8000)
def func_start(va):
    for a in range(va, max(lo,va-0x4000), -4):
        if is_prologue(a):
            prev=word(a-8)   # jr $ra is usually 2 back (jr + delay)
            if prev==0x03e00008 or word(a-4)==0 or word(a-8)==0: return a
            return a
    return None

for va in range(lo,hi,4):
    w=word(va)
    if (w>>26)!=3: continue
    tgt=((va+4)&0xf0000000)|((w&0x03ffffff)<<2)
    if tgt in targets:
        fs=func_start(va)
        print("jal 0x%08x  at 0x%08x   (in func 0x%08x)"%(tgt,va,fs or 0))
