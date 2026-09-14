# Patching the disc

Both games authenticate against Sony's DNAS before they will talk to Konami's
servers. Sony shut DNAS down permanently, so the check can never pass, on an
emulator or on real hardware. DNAS tickets are signed by Sony, so no server can
answer for it either, so the verdict has to be overridden on the client. That is
the whole reason a patch exists.

The patch changes 4 bytes in Extreme 2 and 160 bytes in SuperNOVA. It touches
nothing else.

## What you need

Your own copy of the game, dumped to a `.iso`. This project ships no game data
and never will; the patch is a difference, and it is useless without the disc.

| game | serial | source sha1 | size |
|---|---|---|---|
| Extreme 2 (USA) | SLUS-21174 | `b2087cecb653aafdc09ba389169e8f25148f0d6c` | 3917185024 |
| SuperNOVA (USA) | SLUS-21377 | `810d0b68b2fdbebf27cf80380f4427c63e712084` | 1574731776 |

Those are the Redump dumps. Check yours first:

```sh
sha1sum "Dance Dance Revolution SuperNOVA (USA).iso"     # Linux / macOS / Git Bash
certutil -hashfile "...iso" SHA1                         # Windows
```

If it does not match, the `.xdelta` will refuse to apply rather than produce a
broken disc. A raw 2352-byte-sector `.bin` will not work; you need a 2048-byte
`.iso`.

## Applying the patch

Download the `.xdelta` for your game from the Releases page.

GUI, any platform, with [DeltaPatcher](https://github.com/marco-calautti/DeltaPatcher):
pick the original ISO, pick the `.xdelta`, press Apply.

Command line:

```sh
xdelta3 -d -s "Dance Dance Revolution SuperNOVA (USA).iso" \
  Dance-Dance-Revolution-SuperNOVA-USA-online.xdelta \
  "Dance Dance Revolution SuperNOVA (USA) [ONLINE].iso"
```

`scoop install xdelta` on Windows, `apt install xdelta3` on Debian/Ubuntu,
`brew install xdelta` on macOS.

Or from this repository, if you would rather not install a patcher:
standard library Python, nothing to install:

```sh
python3 tools/isopatch.py "SuperNOVA (USA).iso" "SuperNOVA (USA) [ONLINE].iso"
python3 tools/isopatch.py --dry-run "SuperNOVA (USA).iso"   # verify, write nothing
```

It verifies every original byte before it writes anything, and produces a file
identical to the one the `.xdelta` gives you.

## Real hardware

The patched image is a normal disc image. Burn it to DVD-R, or load it over the
network or from USB/HDD with Open PS2 Loader, the same as any other backup.

Do not try this with a cheat device on SuperNOVA. CodeBreaker, Action
Replay and OPL's built-in cheat engine all write to memory every frame, and
SuperNOVA's DNAS2 code lives at `0x00a46000`, an overlay slot shared by
`DATA03.BIN` (`net_mas4`) and `DATA04.BIN` (`netlby_mas4`). A repeating write
there corrupts whichever module happens to be resident. This is why SuperNOVA
needs a disc patch and not a code. Extreme 2's patch is in the always-mapped
main ELF and does not have this problem.

## PCSX2

Either use the patched image, or for Extreme 2 only, drop
`patches/SLUS-21174_E8FB7A7F.pnach` into your PCSX2 `cheats/` folder and run the
unpatched disc. Both do the same thing.

Two things that will silently waste your time:

- The pnach must have **no `[Section]` header**. Patches under a header are
  individually-toggleable cheats and default to disabled, and PCSX2 logs
  `Found 1 cheats in ...pnach` either way, so the file looks loaded while doing
  nothing.
- The filename must be `<serial>_<CRC>.pnach`. A bare `<CRC>.pnach` is the
  PCSX2 1.6 convention and is ignored without a message.

There is no working pnach for SuperNOVA, for the overlay reason above.
`patches/SLUS-21377_23EFA2AF.pnach` is kept only as a record of what that
address really is; it is a no-op.

## After patching

The patch gets you past DNAS. It does not point the game at a server. Both
games find theirs by DNS, so you also need the console's DNS to answer for the
`konamionline.com` names. See the main [README](../README.md) for the name list
and [server/README.md](../server/README.md) for a working resolver setup.

Extreme 2 additionally needs a network configuration on the memory card and
ships no tool to create one. SuperNOVA bundles Sony's configuration utility, so
build the configuration in SuperNOVA first.

## Rebuilding the patches

For maintainers. `tools/mkpatch.py` reads the same manifest
(`patches/patches.json`) that `isopatch.py` does, applies it to the reference
dump, encodes the delta, then decodes it again and checks the result hashes back
to the patched image. A patch that has not round-tripped is not published.

```sh
python3 tools/mkpatch.py "Dance Dance Revolution SuperNOVA (USA).iso"
```

Output lands in `patches/dist/`, which is not tracked. The built patches are
release assets rather than repository content, so the tree itself stays free of
anything derived from the disc:

```sh
gh release create v1.0 --title "Disc patches" --notes-file docs/patching.md patches/dist/*.xdelta patches/dist/*.json
```

Each `.xdelta` ships with a `.json` recording the source dump it was built from,
the sha1 of the image it produces, and its own sha1.
