# Cheat codes, for the original disc

This is the other way past DNAS. Instead of patching a disc image, a cheat
engine makes the same edits in memory while the game runs, so the disc in the
drive can be the one you bought.

`patches/cheats/DDR-Online.txt` holds the codes for all three games.

Use this if you are booting a real disc on a FreeMcBoot console. If you are
loading an image from USB, HDD or the network, patch the image instead
([patching.md](patching.md)). That is fewer moving parts, and it is the route
that has actually been run end to end.

## What you need

- A console with FreeMcBoot, or FreeDVDBoot, or any other way to run homebrew.
- [Cheat Device PS2](https://github.com/root670/CheatDevicePS2) by root670. It
  boots retail discs and applies codes to them, which is the specific thing
  needed here. OPL's cheat engine cannot help, because OPL does not boot the
  disc drive.
- `patches/cheats/DDR-Online.txt` from this repository.

## Setting it up

Put `DDR-Online.txt` somewhere the console can read, a USB stick being easiest,
and point Cheat Device at it. Settings live in `CheatDevicePS2.ini`, in the
directory Cheat Device itself is run from:

```ini
[CheatDevicePS2]
databaseReadOnly=mass:/DDR-Online.txt
```

`mc0:/DDR-Online.txt` works too if you would rather keep it on the memory card.
Cheat Device can merge several databases, so this file can sit alongside the
big community one. Nothing in it collides.

Then:

1. Launch Cheat Device from FreeMcBoot.
2. Pick **Dance Dance Revolution Extreme 2 (USA) [SLUS-21174]**,
   **Dance Dance Revolution SuperNOVA (USA) [SLUS-21377]** or
   **Dance Dance Revolution SuperNOVA 2 (USA) [SLUS-21608]** from the game
   list.
3. Turn on **DNAS bypass (required)**. For either SuperNOVA also turn on
   **Service URLs**, unless you have a reason not to. See below.
4. Back out to the boot menu and choose **==Disc==**. It asks for the disc,
   reads `SYSTEM.CNF` off it, and boots the game.

The **Enable Code** does not need to be switched on by hand. A cheat that
contains nothing but a 9-type hook code is enabled automatically as soon as any
other cheat in that game is on.

## What the codes do

Extreme 2 gets two cheats and each SuperNOVA three, and they are the same edits
`tools/isopatch.py` writes into an image. Both sets are generated from
`patches/patches.json` by `tools/mkcheats.py`, so the two routes cannot drift
apart.

**Enable Code.** A 9-type hook. It tells the engine to install its per-frame
jump at one instruction inside the game's pad-reading routine, and gives the
opcode it expects to find there. The engine compares that word first and does
nothing if it does not match, which is what keeps the codes off the loader and
off the other game. Without a hook code the engine goes looking for one by
itself and can crash whatever it finds, so leave this cheat in the file.

**DNAS bypass.** Extreme 2 is two words in the always-mapped main ELF, the same
two the PCSX2 pnach writes. SuperNOVA is four words, and they need the guard
described below.

**Service URLs**, SuperNOVA only. The game's service table points at
`https://dx2web.konamionline.com/...` on ports 80 and 443. This rewrites those
five URLs to plain HTTP on port 19580, which is where `server/web.py` listens,
and shortens the paths to fit the original string slots. Leave it off only if
you have changed the URLs some other way. Without it the registration form, the
agreement text and the news feed all try to reach a host that answers on
neither port, and the registration URL is HTTPS, which this server does not
speak.

## Why SuperNOVA's codes have two extra lines

A plain pnach cannot do SuperNOVA at all, and [patching.md](patching.md)
says so. A cheat engine that can test memory first can.

SuperNOVA's DNAS2 verdict is decided inside `net_mas4`, which the game loads at
`0x00a46000`. That address is an overlay slot: the boot ELF maps nine program
headers there, so nine different modules take turns living at it. A code that
writes to `0x00a46fc0` every frame will sooner or later write into whichever
one of the other eight is resident, and corrupt it.

The fix is to look before writing. The first two lines of the cheat are D-type
conditionals. They test the word already at `0x00a46fc0` against `0c2a2078`,
the `jal` that the patch replaces, and let the four writes through only if it
matches:

```
D0A46FC2 05000C2A     high half of the signature, then the next 5 lines
D0A46FC0 04002078     low half, then the next 4
20A46FC0 24030005     li   $v1, 5
20A46FC4 AE030058     sw   $v1, 0x58($s0)
20A46FC8 00001021     move $v0, $zero
20A46FCC 00000000     nop
```

`tools/mkcheats.py` reads every `DATA*.BIN` in a retail image and refuses to
emit this cheat unless that signature is unique to `DATA03.BIN`. On the USA
disc it is. The other twelve modules hold something else at that offset.

The guard has a second, useful effect. The signature is the word the first
write destroys, so once the patch has landed the condition stops matching and
the codes go quiet. If the game swaps `net_mas4` back in later, the signature
comes back with it and they re-apply.

## Verified how far

Every address, opcode, string and file offset in the generated file was read
out of the retail USA images and checked before it was written there, including
the two published enable codes, which match these exact ELFs word for word.

The codes are then run. `tools/mkcheats.py` executes the lines it is about to
emit against the files they target and requires three things: that the result
is the patched disc byte for byte, that the guarded cheat writes nothing at all
into any of the other twelve modules, and that it stops writing once the patch
has landed. Any of those failing is an error rather than a warning, and no file
is written. `tools/mkcheats.py --check <iso>` does the same against your own
dump and writes nothing either way.

Applying the shipped file to a retail image also reproduces the `[ONLINE]`
image `tools/isopatch.py` builds, for all three files it touches. That is the
statement that the two routes are the same patch.

What has not been done is a boot on a console with these codes. If something
misbehaves, in order of likelihood:

- **Nothing happens at all.** The hook never installed. Check that the game
  list entry you enabled is the right one, and that the DNAS cheat is on.
- **Extreme 2 still fails DNAS.** `201D5280` is in the main ELF and unguarded,
  so if this fails the engine is not running at all. Try another Cheat Device
  build.
- **SuperNOVA hangs where it used to hang.** The DNAS2 scene never saw the
  patch. The four writes are gated, so the likeliest cause is that the guard
  never matched, which a different disc region would do. Run
  `tools/mkcheats.py --check` on your own dump.
- **SuperNOVA crashes some time after the lobby.** That would mean the writes
  landed on the wrong module, which is the thing the guard exists to prevent.
  Turn the cheat off and say so. That finding matters more than the cheat does.

## This is not the whole setup

Getting past DNAS only stops the game refusing to start. It still has to find
your server, which it does by DNS: the console's resolver has to answer for the
`konamionline.com` names. The [README](../README.md) lists them.

Extreme 2 also needs a network configuration on the memory card and ships no
way to create one. SuperNOVA includes Sony's configuration tool, so if you have
both discs, build the configuration in SuperNOVA first.

## Rebuilding the file

For maintainers. The codes are generated, not written by hand:

```sh
python3 tools/mkcheats.py "DDR Extreme 2 (USA).iso" "DDR SuperNOVA (USA).iso"     "DDR SuperNOVA 2 (USA).iso"
```

SuperNOVA 2 has no published enable code. Its hook, `90128C00 00832021`, is
the same libpad site as SuperNOVA's `901273B8`, found by lining up the two
executables, and its codes have been checked by `mkcheats.py`'s simulation but
not yet on a console.

It verifies every byte against the images, re-cuts the unaligned string edits
into word writes, proves the overlay guard is unique, runs the result, and
writes `patches/cheats/DDR-Online.txt`. `--check` verifies and writes nothing.

The same code lines are what OPL's built-in cheat engine and PS2rd take, all
three being the same engine, so an image on USB or HDD can use them instead of
the disc patch. Their cheat files are one game per file and named after the
serial. See their own documentation for where the file goes.
