import sys, re
from capstone import *
path, foff, vbase = sys.argv[1], int(sys.argv[2],0), int(sys.argv[3],0)
d = open(path,'rb').read()
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN)
def dis(va):
    f = va-vbase+foff
    g=list(md.disasm(d[f:f+4],va))
    return (g[0].mnemonic, g[0].op_str) if g else ('.word','?')
for line in sys.stdin:
    line=line.strip()
    if not line.startswith('001') and not line.startswith('002'): continue
    va=int(line.split()[0],16)
    if ' sw ' not in line and ' sb ' not in line and ' sh ' not in line: continue
    print("--- store @ %08x" % va)
    for k in range(-5,2):
        a=va+k*4
        m,o=dis(a)
        print("   %08x  %-6s %s" % (a,m,o))
