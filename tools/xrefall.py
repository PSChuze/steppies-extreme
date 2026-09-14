import sys, struct
# xrefall.py <elf> <textfileoff> <vbase> <strings_file> <regex>
import re as _re
path, foff, vbase = sys.argv[1], int(sys.argv[2],0), int(sys.argv[3],0)
strfile, pattern = sys.argv[4], sys.argv[5]
d = open(path,'rb').read()
def f2v(f): return f - foff + vbase
targets = {}
for line in open(strfile, errors='replace'):
    try: o,s = line.split(' ',1)
    except: continue
    s = s.rstrip('\n')
    if _re.search(pattern, s): targets[int(o,16) - foff + vbase] = s
print("# %d target strings" % len(targets), file=sys.stderr)
lui = {}
found = {}
for off in range(foff, len(d)-3, 4):
    w = struct.unpack_from('<I', d, off)[0]
    op = w >> 26
    if op == 0x0f:
        lui[(w>>16)&0x1f] = (w & 0xffff, off)
    elif op == 0x09:  # addiu rt, rs, imm
        rs, rt, imm = (w>>21)&0x1f, (w>>16)&0x1f, w & 0xffff
        if rs in lui:
            hi, luioff = lui[rs]
            if off - luioff <= 256:
                simm = imm - 0x10000 if imm & 0x8000 else imm
                a = ((hi<<16) + simm) & 0xffffffff
                if a in targets:
                    found.setdefault(a, []).append(f2v(off))
for a in sorted(found):
    print("0x%08x  %-32s <- %s" % (a, targets[a], ", ".join("0x%08x"%x for x in found[a])))
