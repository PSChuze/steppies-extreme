import sys, struct, re
from capstone import *
path, foff, vbase = sys.argv[1], int(sys.argv[2],0), int(sys.argv[3],0)
lo, hi = int(sys.argv[4],0), int(sys.argv[5],0)
off = int(sys.argv[6],0)
d = open(path,'rb').read()
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN)
md.detail = False
hits=[]
for va in range(lo, hi, 4):
    f = va - vbase + foff
    w = d[f:f+4]
    if len(w)<4: break
    g = list(md.disasm(w, va))
    if not g: continue
    i=g[0]
    if i.mnemonic in ('lw','sw','lh','sh','lhu','lbu','lb','sb','ld','sd'):
        m = re.search(r'(-?0x[0-9a-fA-F]+|-?\d+)\(\$\w+\)', i.op_str)
        if m and int(m.group(1),0) == off:
            hits.append((va, i.mnemonic, i.op_str))
for va,m,o in hits:
    print("%08x  %-5s %s" % (va,m,o))
print("total", len(hits))
