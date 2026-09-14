import sys, re, struct
from capstone import *
path, foff, vbase = sys.argv[1], int(sys.argv[2],0), int(sys.argv[3],0)
start, end = int(sys.argv[4],0), int(sys.argv[5],0)
d = open(path,'rb').read()
def v2f(v): return v - vbase + foff
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN)
strs = {}
if len(sys.argv) > 6:
    for line in open(sys.argv[6], errors='replace'):
        try:
            o, s = line.split(' ',1); strs[int(o,16) - foff + vbase] = s.rstrip('\n')
        except: pass
last_lui = {}
for va in range(start, end, 4):
    w = d[v2f(va):v2f(va)+4]
    if len(w) < 4: break
    got = list(md.disasm(w, va))
    if not got:
        print("%08x  .word    0x%08x" % (va, struct.unpack('<I', w)[0])); continue
    i = got[0]; m, op, ann = i.mnemonic, i.op_str, ""
    if m == 'lui':
        try:
            r,v = op.split(', '); last_lui[r.strip()] = int(v,0)
        except: pass
    elif m in ('addiu','ori','lw','sw','lbu','lb','lh','lhu','sb','sh','lwu','ld','sd'):
        mm = re.search(r'(-?0x[0-9a-fA-F]+|-?\d+)\((\$\w+)\)', op)
        base = imm = None
        if mm: imm, base = int(mm.group(1),0), mm.group(2)
        else:
            parts=[p.strip() for p in op.split(',')]
            if len(parts)==3 and parts[1].startswith('$'):
                base=parts[1]
                try: imm=int(parts[2],0)
                except: imm=None
        if base in last_lui and imm is not None:
            a = ((last_lui[base]<<16)+imm) & 0xffffffff
            ann = "   ; =0x%08x" % a
            if a in strs: ann += '  "%s"' % strs[a][:60]
    print("%08x  %-9s %-42s%s" % (va, m, op, ann))
