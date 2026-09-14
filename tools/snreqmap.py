"""snreqmap.py, SuperNOVA: request opcode -> the function that issues it.

sndispmap.py answers "what comes back". This answers "who asks", which is the
half you need in order to say which RPCs a game mode actually uses, and to tell
a request the client can send from one it never will.

Every request issuer does two things:

    *(ctx + 0x2370) = <opcode>    ; the in-flight request field that EVERY
                                  ; response parser validates against
    <transport>(conn, <opcode>)   ; 0x002715b0 if the request has no body,
                                  ; otherwise one of the request builders

Neither one alone finds them all, so this runs both and takes the union:

  * `call`  -- the opcode as the transport's $a1. Misses the issuers that park
               it in $v0 first (0x441d is one).
  * `store` -- the opcode in a `sw rX, 0x2370(rY)`. Misses the ones that build
               the constant with lui/ori, which this deliberately does not
               track rather than guess at register liveness.

Scanning for the opcode immediate on its own is not an option: every response
parser compares against both its own opcode and its request's, so each opcode
appears three or four more times in code that sends nothing.

usage: snreqmap.py [elf]
"""
import struct, sys

PATH = sys.argv[1] if len(sys.argv) > 1 else 'work/iso/sn/SLUS_213.77'
FO, VB = 0x280, 0x100000
TEXT_END = VB + 0x204780
INFLIGHT = 0x2370
# 0x002715b0 sends a bodiless request; the rest open a request builder.
SEND = (0x002715b0, 0x0027a330, 0x0026a5a0)

d = open(PATH, 'rb').read()


def w32(va):
    o = va - VB + FO
    return struct.unpack_from('<I', d, o)[0] if 0 <= o < len(d) - 3 else None


def func_start(va):
    """Nearest preceding `addiu $sp,$sp,-N`, or the end of the previous
    function -- whichever comes first walking back.

    Several issuers are leaves with no stack frame (0x441d's is), and a
    prologue-only walk sails straight past them into the previous function,
    reporting that function's parser address as the issuer. Stopping at the
    previous `jr $ra` catches them.
    """
    for a in range(va, va - 0x800, -4):
        w = w32(a)
        if w is None:
            break
        if (w >> 26) == 9 and ((w >> 21) & 0x1f) == 29 \
                and ((w >> 16) & 0x1f) == 29 and (w & 0x8000):
            return a
        if w == 0x03e00008:            # jr $ra: previous function ended here
            return a + 8
    return None


def is_op(v):
    return 0x0003 <= v <= 0x8fff


found = {}                                   # opcode -> {func: set(methods)}


def add(op, va, how):
    found.setdefault(op, {}).setdefault(func_start(va) or va, set()).add(how)


regv = {}
for va in range(VB, TEXT_END, 4):
    w = w32(va)
    if w is None:
        continue
    op = w >> 26
    if op in (9, 0x0d) and ((w >> 21) & 0x1f) == 0:      # addiu/ori rT,$zero,imm
        v = w & 0xffff
        regv[(w >> 16) & 0x1f] = v if is_op(v) else None
    elif op == 0x0f:                                     # lui clobbers
        regv[(w >> 16) & 0x1f] = None
    elif op == 0x2b and (w & 0xffff) == INFLIGHT:        # sw rT, 0x2370(rS)
        v = regv.get((w >> 16) & 0x1f)
        if v is not None:
            add(v, va, 'store')
    elif op == 3:                                        # jal
        if (((va + 4) & 0xf0000000) | ((w & 0x03ffffff) << 2)) not in SEND:
            continue
        # $a1 = the opcode: the delay slot first, else the last load into $a1.
        for a in [va + 4] + list(range(va - 4, va - 0x40, -4)):
            x = w32(a)
            if x is None:
                continue
            if (x >> 26) in (9, 0x0d) and ((x >> 21) & 0x1f) == 0 \
                    and ((x >> 16) & 0x1f) == 5:
                if is_op(x & 0xffff):
                    add(x & 0xffff, va, 'call')
                break

both = sum(1 for o in found for f in found[o] if len(found[o][f]) == 2)
print('request opcode -> issuing function   [%d opcodes, %d confirmed by both '
      'passes]' % (len(found), both))
print('=' * 70)
for op in sorted(found):
    for fn in sorted(found[op]):
        print('  0x%04x  %08x  %s'
              % (op, fn, '+'.join(sorted(found[op][fn]))))
