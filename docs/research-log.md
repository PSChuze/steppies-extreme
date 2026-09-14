# Research log

How this was worked out, and more usefully, the things that turned out to be
wrong. `protocol.md` says what is true. This says what looked true.

## Method

The client is the only authority left. Konami's servers are gone, there is no
reference implementation and nobody captured a live session. So everything here
came from one of two places: reading the game's code, or serving a guess to a
real client and watching what happened.

The second is slower but settles things the first cannot. A disassembly shows
that a field is a byte indexing a table. Only the client shows which table.

Two habits did most of the work.

Prefer code that compares a value over code that uses it. Where a field indexes
a table you cannot read, the client's own validation often spells out the legal
values as immediates. The nine Ranking Challenge option bytes came from the
check the card builder uses to decide whether a challenge counts as modified.
It states the defaults outright.

Let the client send you the answer. Request bodies are built from the client's
own state, so the shape of anything it sends is free. The result upload is
sixteen bytes of gameplay values, and reading them off a real play beats
deriving them from the overlay that produces them.

## Traps

Scanning for small immediates is useless. `0x2000` matches about 120 places, a
bare `5` or `6` about 250. Scan for a call to a known primitive and read its
argument instead. For a dispatcher, parse the compare chain; `tools/dispmap.py`
got all 55 slot-2 opcodes that way in one pass.

Build candidate opcode lists from the dispatch table, not from traffic you have
seen. Every failed push experiment came from a list of opcodes already observed
on the wire. The opcode that unlocked head-to-head play had never been sent by
anyone, so that method could not have found it. Same story later with the
week-rollover push.

Check the direction of an access before naming a global. One address got
recorded as a peer count on the strength of a read. It has 91 loads and 17
stores, and every store is in the match code: it is a game mode, set after
matchmaking. That one mislabel sent a whole round of work after the wrong
blocker.

The request opcode is not the response minus one. `0x3020` answers with
`0x3022`, `0x3030` with `0x3032`, `0x5009` with `0x5010`. Guessing `+1` cost a
17-second client timeout that looked exactly like a server fault.

Unsolicited pushes go out after the in-flight reply, but not immediately after.
The client tests "last received opcode", so a push sent first is overwritten
before anything can act on it. Sent too soon after the reply, it clobbers the
reply for the same reason: the waiting call only samples that field once a
frame.

The main executable is not the whole program. Twice this project concluded that
nothing writes a value and some other layer must be responsible. Both times the
answer was in code that had not been searched, once in an overlay and once on
the store side of a scan. Scan every binary, and count loads separately from
stores, before deciding a value is never written.

When a struct holds two strings, the consumer identifies them, not the parser.
That settled the local and public address pair in the match record, and found an
address/name mix-up in the server list after it had blocked account connection
for a day.

Do not scan displacements to find a struct's consumers. A decompiler prints
`*(char *)(x + 0x244d)` for code that computes a base once and loads at `+9`, so
a displacement scan misses exactly what you are looking for. Scan for where an
offset is materialised instead. `tools/scanconst.py` does that, and
`tools/scanfield.py` extends it to accesses through a base pointer built
earlier, which is how most struct fields are really touched.

A theory that is also true of a working capture is not a cause. This one cost
the most. An online lobby hang got blamed in turn on a null pointer, an
unpopulated buffer, and an allocator running past the end of its block. All
three were coherent, all three explained the symptom, all three were wrong. Each
died the same way: capture the same screen while it works, compare, find the
supposed cause identical in both. The real cause was a single song id in a
message the server sends, found by bisecting the ids rather than by reasoning
about mechanism at all.

Get a working capture early.

## Tools

Standard library plus `capstone`. They read the extracted binaries rather than a
decompiler project, so they keep working when a decompiler install does not.

| tool | answers |
|---|---|
| `dispmap.py` | where a dispatcher routes each opcode, by parsing its compare chain |
| `reqmap.py` | which request opcode each named RPC sends |
| `scanconst.py` | where a constant or struct offset is materialised |
| `scanfield.py` | what reads or writes an address, including through a computed base |
| `blockwriters.py` | what writes through a pointer held in a global |
| `scanaddr.py` | loads and stores against a fixed address |
| `xrefall.py` | what references which strings |
| `ps2dis.py` | annotated disassembly of a range |
| `pine.py`, `pinewatch.py` | live memory from a running client |

## Savestates

Often faster than live debugging, because you can compare two of them. They are
zip archives, but the members are zstd compressed and `zipfile` cannot unpack
them on its own. Read the member's raw bytes and hand them to `zstandard`.

Worth knowing: `eeMemory.bin` is 32 MB of main memory, `eeHwRegs.bin` has the
DMA and GIF registers, and `Screenshot.png` is the quickest way to tell what a
capture actually was.
