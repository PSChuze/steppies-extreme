# SuperNOVA, getting the binaries into Ghidra

Until now the Ghidra project held Extreme 2 only, and every SuperNOVA finding
had to come out of hand-written capstone scans. This is what it took to make
`tools/dc.sh` work on SuperNOVA, and the three traps that cost time doing it.

## Trap 1. Ghidra auto-detects the wrong MIPS

Importing `SLUS_213.77` with no `-processor` gives
`MIPS:LE:64:64-32R6addr`. Release 6 *removed* the branch-likely
instructions, so every `beql`/`bnel` decodes as "Unable to resolve constructor"
and the function truncates to `halt_baddata()`, which looks exactly like the
`sq`/`lq` problem and is not it. Import with the language named:

```
-processor "MIPS:LE:64:64-32addr" -cspec o32
```

## Trap 2, `analyzeHeadless.bat` ends in `pause`

Without `< /dev/null` the batch file sits at "Press any key to continue" holding
the project lock, and the run appears to hang or the next run fails with
"Requested project program file(s) not found". `tools/dc.sh` now redirects.

## Trap 3, `sq`/`lq`, and where to stop rewriting

Ghidra does not model the EE's 128-bit register halves, so any function that
spills with `sq` decompiles to `halt_baddata()`. `tools/sqlq.py` rewrites the
6-bit opcode, `lq` `0x1e` → `ld` `0x37`, `sq` `0x1f` → `sd` `0x3f`, same I-type
layout, into a `.ghidra.` copy that is **for reading only**.

The bound matters. The text segment also holds rodata, pointer tables and
every song title in the game, and `0x1e`/`0x1f` is a common leading byte in
ASCII-adjacent data, so a whole-segment sweep corrupts strings (`"zarc"` →
`"\xde arc"`). `sqlq.py` stops at the last `jr $ra`; on `SLUS_211.74` that drops
373 false rewrites relative to the copy this project had been using, and drops
no real ones, everything past the bound is pointer tables and text.

Verified by regenerating `SLUS_211.ghidra.74`: the new output is a strict subset
of the old, differing only in those 373 data words.

## Import commands

```sh
python tools/sqlq.py work/iso/sn/SLUS_213.77 work/iso/sn/SLUS_213.ghidra.77
python tools/sqlq.py work/iso/sn/DATA04.BIN work/iso/sn/DATA04.ghidra.BIN 0x40 0x23740

analyzeHeadless <proj> DDR64 -import SLUS_213.ghidra.77 \
    -processor "MIPS:LE:64:64-32addr" -cspec o32 -overwrite < /dev/null

analyzeHeadless <proj> DDR64 -import DATA04.ghidra.BIN \
    -processor "MIPS:LE:64:64-32addr" \
    -loader BinaryLoader -loader-baseAddr 0x00a46000 -overwrite < /dev/null
```

Overlays share load addresses, so each one is its own program.

## The overlay container

Every `DATAnn.BIN` is a 0x40-byte header followed by the image, and **the header
is part of what gets loaded**, so `VA = file offset + base`, with no adjustment.

| offset | field |
|---|---|
| `0x00` | `"MWo3"` |
| `0x04` | u32 module index |
| `0x08` | u32 **load base** |
| `0x0c` | u32 text size |
| `0x10` | u32 data size |
| `0x14` | u32 bss size |
| `0x18` | u32 base + file size |
| `0x20` | name, NUL-terminated |

Both invariants hold on all thirteen files: `0x40 + text + data == filesize`,
and `base + filesize == [0x18]` (DATA11 differs on the second).

## The thirteen overlays

`DATA10`–`DATA12` are on the disc but were never extracted; with them the count
matches the ELF's thirteen overlay program headers exactly, nine in the
`0x00a46000` slot, four in `0x00a86000`.

| file | module | slot |
|---|---|---|
| DATA00 | `opt_mas4` | a46000 |
| DATA01 | `rec_mas4` | a46000 |
| DATA02 | `workout_mas4` | a46000 |
| DATA03 | `net_mas4` | a46000 |
| DATA04 | `netlby_mas4` | a46000 |
| DATA05 | `link_mas4` | a46000 |
| DATA06 | `smm_mas4` | a46000 |
| DATA07 | `net_dnas_mas4` | a46000 |
| DATA08 | `net_https_mas4` | a46000 |
| DATA09 | `edit_mas4` | a86000 |
| DATA10 | `tra_mas4` | a46000 |
| DATA11 | `shop_mas4` | a86000 |
| DATA12 | `adv_mas4` | a86000 |

## `tools/snreqmap.py`, the other half of the dispatch map

`sndispmap.py` answers "what comes back". `snreqmap.py` answers "who asks", and
finds **61 request opcodes**, the complete client-side request inventory.

Every issuer stores its opcode into `ctx+0x2370`, the same in-flight field every
response parser validates, and then calls a transport. Neither signal alone is
enough, so the tool runs both passes and takes the union:

- keying on the **call** misses issuers that park the opcode in `$v0` first
  (`0x441d` is one), because there are four send entry points and the opcode
  does not reliably arrive in `$a1`;
- keying on the **store** misses issuers that build the constant with
  `lui`/`ori`.

23 of the 61 are found by both. Scanning for the opcode immediate alone does not
work at all: every response parser compares against both its own opcode and its
request's, so each opcode appears three or four more times in code that sends
nothing.

One detail worth keeping: several issuers are leaves with no stack frame, so a
prologue-only "find the function start" walk sails past them into the previous
function and reports a *parser* address as the issuer. Stop at the previous
`jr $ra` as well.

## `tools/snblocks.py`, the third method, for what the other two cannot see

`sndispmap.py` answers "what comes back" and `snreqmap.py` answers "who asks".
Both key on the in-flight request field at `ctx+0x2364+0xc`, and some families
do not use it: the friends list keeps its state at `ctx+0x2c64` instead, so
neither tool sees its group, and answering `0x3080` with the `+1` guess froze
the client.

`snblocks.py` groups parsers by the state block each one drives, which is the
same grouping arrived at from the other side. It reproduces two groups already
known from the in-flight compare, `0x5030` on `ctx+0x13cd0`, `0x5034` on
`ctx+0x13f40`, and finds a third of the same shape that was still unserved,
`0x5040` on `ctx+0x13038`.

The trick that makes it work is symbolic register tracking, `ctx+K` and
constants, over each parser. Large displacements are built as
`lui r,1 ; addu r,ctx,r ; sw rX,0x42xx(r)`, so:

- a **displacement** scan sees `0x42xx` but does not know the base;
- `scanconst.py` looks for the offset being materialised, and the constant
  materialised here is `0x10000`, far too common to scan for.

Only tracking the addition resolves the field. The one thing the tracker cannot
do is follow a branch, so a register set only on the taken path is lost;
`0x4411` and `0x4351` both set their flag that way. The tool backstops itself
with a displacement scan of the ELF and attributes each store to the parser
that contains it.

The same pass prints the **push → event flag → reader** table, which is how
SuperNOVA's matchmaking mechanism was found. See
[protocol.md](protocol.md#matchmaking-supernova).

## The field codec

From `0x00279a60`–`0x0027a300`. The message keeps a read cursor at `msg+0x454`
over a payload at `msg+0x40`, with the length at `msg+4`.

| function | reads |
|---|---|
| `0x0027a300` | rewind cursor (begin parse) |
| `0x00279a60` | **"anything left?"**, returns `-1` when the cursor reaches the length, and **consumes nothing** |
| `0x00279c70` | u32 BE |
| `0x00279b90` | s32 BE |
| `0x00279d30`, `0x00279d80` | u16 BE: **two identical copies** |
| `0x00279dd0`, `0x00279e10` | u8: **two identical copies** |
| `0x00279b10(dst, n)` | `n` raw bytes, then writes a NUL at `dst[n]` |

The duplicates matter, and both halves of this project got them half right.
The compiler emitted two byte-identical copies of the u16 reader and two of the
u8 reader. This table used to list only `0x00279d30` and `0x00279dd0`;
`sndispmap.py`'s table listed only the *other* copy of each, `0x00279d80` and
`0x00279e10`, and it labelled them `u16b` and `u8` as though `0x00279d30` were
a different, little-endian reader. It is not. Both u16 copies are
`lb hi@+0x40 ; lbu lo@+0x41 ; sll 8 ; or`: **big-endian, and there is no
little-endian u16 reader in the codec at all.**

The cost of the missing u8 was real. Any field read through the copy the tool
did not know was invisible, so the reported body was **short**, which is the
one error this protocol punishes silently, because the parsers bounds-check the
read cursor and not the message. Five shapes were wrong: `0x3921` (66 → 68),
`0x4324` (53 → 55), `0x4a04` and `0x4a13` (64 → 67), and every `0x8002` record
(8 → 13). Only `0x8002` was actually being served, and `gate.py` had it right
from the live trace, so nothing shipped broken, but the match record was
decoded from the short shape first and had to be redone.

Found by fingerprinting every function in the codec region that opens by
loading the cursor at `msg+0x454`; those four are the only duplicates.

The consequence for anyone writing bodies: **looping list records have no
delimiter and no count.** A DATA message is just records back to back, and the
parser stops when the payload runs out. An empty body is therefore a
well-formed empty list, not a short read, but only for the loop parsers.
