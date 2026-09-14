"""sqlq.py <in> <out> [textoff] [textlen]

Rewrite the PS2-only 128-bit `lq`/`sq` into `ld`/`sd` so Ghidra can decompile.

Ghidra's MIPS decompiler does not model the EE's 128-bit GPR halves. Every
function containing an `lq` or `sq` -- which is most of the register-heavy ones,
because the EE ABI spills callee-saved registers with `sq` -- decompiles to
`halt_baddata()`. `lq`/`sq` are I-type with the same rs/rt/imm layout as
`ld`/`sd`, so swapping the 6-bit opcode is a one-word edit that keeps every
address, offset and register intact. The low 64 bits are what the game's own
code actually reads back, so the decompilation is faithful for anything that is
not genuinely 128-bit.

    lq  = 0x1e -> ld  = 0x37
    sq  = 0x1f -> sd  = 0x3f

THE OUTPUT IS FOR READING ONLY. It is not a runnable executable and must never
be fed to anything that emits a patch -- an address read out of it is fine, an
instruction encoding copied out of it is not. That is why the rewritten copies
carry `.ghidra.` in the name.

Only the CODE part of the text segment is touched. The segment also holds
rodata -- pointer tables and every song title in the game -- and 0x1e/0x1f is a
common leading byte in ASCII-adjacent data, so a whole-segment sweep silently
corrupts strings ("zarc" -> "\xde arc"). The code ends at the last `jr $ra`;
everything past it is data. On SLUS_211.74 that bound removes 373 false
rewrites relative to the copy this project was using before, and removes no
real ones -- the region past the bound is pointer tables and text.
"""
import struct, sys

src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, 'rb').read())

# Default to the first PT_LOAD, which is the text segment in both games' ELFs.
if len(sys.argv) > 4:
    off, ln = int(sys.argv[3], 0), int(sys.argv[4], 0)
else:
    phoff = struct.unpack_from('<I', d, 0x1c)[0]
    off, ln = struct.unpack_from('<II', d, phoff + 4)[0], \
        struct.unpack_from('<I', d, phoff + 16)[0]

# The code/rodata boundary: the last `jr $ra` in the segment. Nothing after it
# is executed, so nothing after it should be rewritten.
end = off
for o in range(off, min(off + ln, len(d) - 3), 4):
    if struct.unpack_from('<I', d, o)[0] == 0x03e00008:
        end = o + 8
ln = end - off

MAP = {0x1e: 0x37, 0x1f: 0x3f}
n = {0x1e: 0, 0x1f: 0}
for o in range(off, min(off + ln, len(d) - 3), 4):
    w = struct.unpack_from('<I', d, o)[0]
    op = w >> 26
    if op in MAP:
        n[op] += 1
        struct.pack_into('<I', d, o, (MAP[op] << 26) | (w & 0x03ffffff))

open(dst, 'wb').write(bytes(d))
print('text 0x%x..0x%x  lq->ld %d  sq->sd %d  -> %s'
      % (off, off + ln, n[0x1e], n[0x1f], dst))
