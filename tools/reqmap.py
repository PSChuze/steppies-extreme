"""Map each NetPrg* RPC to its REQUEST opcode.

Every RPC's send path is a 2-instruction thunk in DATA07:
    j     0x0085b7a0          ; common send
    addiu $a1, $zero, <opcode>  ; delay slot = the request opcode
The main ELF's RPC calls `jal <thunk>` in its sub-state 0.
"""
import struct, re, sys, subprocess

ov = open('work/iso/x2/DATA/DATA07.BIN', 'rb').read()
OVB = 0x850000
# 1. thunk address -> request opcode
thunks = {}
for off in range(0, len(ov) - 7, 4):
    w0 = struct.unpack_from('<I', ov, off)[0]
    w1 = struct.unpack_from('<I', ov, off + 4)[0]
    if (w0 >> 26) != 2:                       # j
        continue
    # addiu $a1($5), $zero, imm
    if (w1 >> 26) == 0x09 and ((w1 >> 21) & 0x1f) == 0 and ((w1 >> 16) & 0x1f) == 5:
        imm = w1 & 0xffff
        if 1 <= imm <= 0x7fff:
            thunks[off + OVB] = imm
print("send thunks found in DATA07: %d" % len(thunks))

# 2. RPC function ranges from the debug-string xrefs
elf = open('work/iso/x2/SLUS_211.74', 'rb').read()
FOFF, VB = 0x200, 0x100000
out = subprocess.run([sys.executable, 'tools/xrefall.py', 'work/iso/x2/SLUS_211.74',
                      '0x200', '0x00100000', 'out/x2.strings.txt', '^NetPrg'],
                     capture_output=True, text=True).stdout
funcs = []
for line in out.splitlines():
    m = re.match(r'0x([0-9a-f]+)\s+(\S+)\s+<- (.*)', line)
    if not m:
        continue
    refs = [int(x, 16) for x in m.group(3).split(', ')]
    funcs.append((min(refs), max(refs), m.group(2)))
funcs.sort()

def owner(va):
    prev = None
    for lo, hi, name in funcs:
        if va < lo:
            return prev or name
        prev = name
    return prev

# 3. jal <thunk> inside each RPC body
res = {}
for off in range(FOFF, len(elf) - 3, 4):
    va = off - FOFF + VB
    if not (0x001d7000 <= va <= 0x001e6700):
        continue
    w = struct.unpack_from('<I', elf, off)[0]
    if (w >> 26) == 3:                        # jal
        tgt = (w & 0x3ffffff) << 2
        if tgt in thunks:
            res.setdefault(owner(va), set()).add(thunks[tgt])
print()
print("%-28s %s" % ("RPC", "REQUEST opcode(s)"))
for lo, hi, name in funcs:
    if name in res:
        print("%-28s %s" % (name, " ".join("0x%04x" % o for o in sorted(res[name]))))
