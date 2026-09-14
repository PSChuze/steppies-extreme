"""scanfield.py <target_vaddr...> -- find every load/store that lands on an
absolute address, INCLUDING accesses through a base pointer built with
lui+addiu/ori and then used with a displacement.

tools/scanaddr.py only resolves `lui $r,hi` + `lw $x,lo($r)`. Real code very
often materialises a STRUCT BASE once (`lui $at,0x64; addiu $a0,$at,0x4910`)
and then accesses fields off it (`sw $v0,0x15c($a0)`), which scanaddr cannot
see -- the same blind spot docs/protocol.md warns about for displacements,
from the other side. This tracks a small constant-register map instead.

Scans the ELF and every DATA0x overlay. Overlay VAs are reported as
<file>+0xNNNN since overlay load addresses vary (DATA07 is 0x850000).
"""
import struct, glob, os, sys

LOADS  = {0x20:'lb',0x21:'lh',0x23:'lw',0x24:'lbu',0x25:'lhu',0x27:'lwu',0x37:'ld',
          0x31:'lwc1',0x35:'ldc1'}
STORES = {0x28:'sb',0x29:'sh',0x2b:'sw',0x3f:'sd',0x39:'swc1',0x3d:'sdc1'}

def scan(data, base_off, vbase, targets, label):
    const = {}          # reg -> (value, va_of_definition)
    out = []
    for off in range(base_off, len(data) - 3, 4):
        va = off - base_off + vbase
        w = struct.unpack_from('<I', data, off)[0]
        op, rs, rt, imm = w >> 26, (w >> 21) & 0x1f, (w >> 16) & 0x1f, w & 0xffff
        if op == 0x0f:                                   # lui
            const[rt] = ((imm << 16), va)
            continue
        if op in LOADS or op in STORES:
            if rs in const and const[rs][0] is not None:
                simm = imm - 0x10000 if imm & 0x8000 else imm
                a = (const[rs][0] + simm) & 0xffffffff
                if a in targets and va - const[rs][1] <= 0x200:
                    out.append((va, 'S' if op in STORES else 'L',
                                (LOADS | STORES)[op], a, const[rs][0], simm))
            if rt in const and (op in LOADS):
                const.pop(rt, None)                      # loaded, no longer constant
            continue
        if op in (0x09, 0x0d):                           # addiu / ori
            src = const.get(rs, (None, 0))[0] if rs else 0
            if src is not None:
                simm = imm - 0x10000 if (op == 0x09 and imm & 0x8000) else imm
                const[rt] = (((src + simm) & 0xffffffff) if op == 0x09
                             else (src | imm), va)
            else:
                const.pop(rt, None)
            continue
        # any other instruction writing rt/rd invalidates it
        if op == 0:                                      # SPECIAL: rd
            const.pop((w >> 11) & 0x1f, None)
        elif op in (0x08, 0x0a, 0x0b, 0x0c, 0x0e, 0x18, 0x19):
            const.pop(rt, None)
    for va, ls, m, a, b, disp in out:
        print("  %s %08x  %s %-5s 0x%08x   = 0x%08x + 0x%x" %
              (label, va, ls, m, a, b, disp))
    return out

if __name__ == '__main__':
    targets = set(int(x, 0) & 0xffffffff for x in sys.argv[1:])
    n = 0
    elf = open('work/iso/x2/SLUS_211.74', 'rb').read()
    n += len(scan(elf, 0x200, 0x100000, targets, 'ELF'))
    for p in sorted(glob.glob('work/iso/x2/DATA/DATA0*.BIN')):
        d = open(p, 'rb').read()
        n += len(scan(d, 0, 0, targets, os.path.basename(p)[:6] + '+'))
    print("--- %d hits" % n)
