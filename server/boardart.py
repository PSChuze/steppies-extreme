#!/usr/bin/env python3
"""Bake the boards' art from your own game discs.

The boards are meant to look like the games, and the only place the games'
art exists is on the discs, which this project does not ship. So this reads
your disc images and writes what the boards draw with into the state
directory:

    python3 boardart.py "DDR SuperNOVA (USA).iso" "DDR Extreme 2 (USA).iso"

or, with docker compose, from the folder holding the images:

    docker compose run --rm -v "$PWD:/discs:ro" boards \\
        python3 boardart.py /discs/*.iso

Each disc is recognised by its serial (SYSTEM.CNF) and baked into
<state>/boardart/<game>/: PNG images, and board.json, which names them, holds
the sprite rectangles and font grids the pages and the Discord images use,
and maps song ids to titles. Discs it does not know are skipped. A patched
[ONLINE] image works as well as a clean one; the art is untouched by the
patches.

Nothing here writes to the disc images. Standard library only.

FORMATS, as read out of the SuperNOVA executable:

  file table   1220 records of 44 bytes in SLUS_213.77: char *name, u32 hash,
               six u32 date fields, u32 index, u32 flags, u32 stored size,
               u32 sector. Sectors are 2048 bytes into DATA/IMAGE.DAT.
  TGCD         the archive compression; decoder at 0x00152140. A 32-byte
               header (magic, unpacked size, packed size, then the constants
               0x7fff 0xffff 0xff 0x8000 the loader checks at 0x001520a0),
               then 4-byte tokens: u16 a. If a & 0x8000, a literal run of the
               next u16's count of bytes follows, padded to 16. Otherwise copy
               u8 length bytes from window + a, where the window starts at
               max(0, position - 0x7fff), then emit one literal byte.
  TIM2         the PS2 SDK texture format; 4- and 8-bit indexed and direct
               colour, alpha 0x80 = opaque.

and out of the Extreme 2 executable, which is a different generation:

  file table   u64 records in SLUS_211.74 at 0x20cfe8, id | lsn << 16 |
               sectors << 40, ending at id 0xffff. No names. lsn counts from
               disc sector 4000, where FILEDATA.BIN starts; FILEDT02-04 follow
               it, so one numbering covers all four. Reader at 0x0011df60.
  Konami LZ    decoder at 0x001769c0. A control byte covers eight items, low
               bit first: 0 is a literal byte, 1 a token t. t < 0x80 copies
               (t >> 2) + 3 bytes from distance (t & 3) << 8 | next byte;
               0x80-0xbf copies ((t >> 4) & 3) + 2 from (t & 15) + 1; 0xff
               ends; 0xc0-0xfe is (t & 0x3f) + 8 literal bytes.
  packages     u32 (offset, size) pairs whose first offset is the table size,
               or a plain list of increasing u32 offsets.
  TCB          Konami's texture: "TCB", sizes, a 4- or 8-bit image and a
               PS2-ordered RGBA palette, like a TIM2 laid out differently.
  songs        wire song id -> internal id through u16[74] at 0x002e7850;
               internal id -> 0xa0-byte record at file offset 0x1d7e90, led
               by its code; entry 4332 holds each internal song's Ranking
               Challenge banner, 224x32.
"""
import json
import os
import re
import struct
import sys
import zlib

SECTOR = 2048


# ── ISO9660 ──────────────────────────────────────────────────────────────────

def iso_files(f):
    """{path: (byte offset, size)} for every file on the disc."""
    f.seek(16 * SECTOR)
    pvd = f.read(SECTOR)
    if pvd[1:6] != b'CD001':
        raise ValueError('not a 2048-byte-sector ISO image')
    out = {}

    def walk(lba, size, prefix):
        f.seek(lba * SECTOR)
        data = f.read(size)
        pos = 0
        while pos < len(data):
            n = data[pos]
            if n == 0:
                pos = (pos // SECTOR + 1) * SECTOR
                continue
            r = data[pos:pos + n]
            pos += n
            raw = r[33:33 + r[32]]
            if raw in (b'\0', b'\1'):
                continue
            name = raw.decode('latin-1').split(';')[0]
            at, sz = struct.unpack_from('<I', r, 2)[0], struct.unpack_from('<I', r, 10)[0]
            if r[25] & 2:
                walk(at, sz, prefix + name + '/')
            else:
                out[prefix + name] = (at * SECTOR, sz)

    rec = pvd[156:190]
    walk(struct.unpack_from('<I', rec, 2)[0], struct.unpack_from('<I', rec, 10)[0], '')
    return out


def read(f, files, name):
    off, size = files[name]
    f.seek(off)
    return f.read(size)


def serial(f, files):
    for line in read(f, files, 'SYSTEM.CNF').decode('latin-1').splitlines():
        if line.upper().startswith('BOOT2'):
            name = line.split('=', 1)[1].strip().replace('\\', '/').split('/')[-1]
            return name.split(';')[0].replace('_', '-').replace('.', '', 1)
    return None


# ── formats ──────────────────────────────────────────────────────────────────

def tgcd(d):
    if d[:4] != b'TGCD':
        return d
    usize = struct.unpack_from('<I', d, 4)[0]
    out = bytearray()
    i = 0x20
    while len(out) < usize:
        a, = struct.unpack_from('<H', d, i)
        if a & 0x8000:
            n, = struct.unpack_from('<H', d, i + 2)
            out += d[i + 4:i + 4 + n]
            i += 4 + n + (-n % 16)
        else:
            ln, c = d[i + 2], d[i + 3]
            src = max(0, len(out) - 0x7fff) + a
            for k in range(ln):
                out.append(out[src + k])
            out.append(c)
            i += 4
    return bytes(out[:usize])


def _colour(b, o, depth):
    if depth == 4:
        r, g, bl, a = b[o:o + 4]
        return bytes((r, g, bl, min(255, a * 2)))
    if depth == 3:
        return bytes(b[o:o + 3]) + b'\xff'
    v, = struct.unpack_from('<H', b, o)
    return bytes(((v & 31) << 3, ((v >> 5) & 31) << 3, ((v >> 10) & 31) << 3,
                  255 if v & 0x8000 else 0))


def tim2(t):
    """[(w, h, rgba bytes)] for every picture in a TIM2 file."""
    if t[:4] != b'TIM2':
        raise ValueError('not a TIM2 (%r)' % t[:4])
    count, = struct.unpack_from('<H', t, 6)
    o = 0x80 if t[5] else 0x10
    out = []
    for _ in range(count):
        total, clut_sz, img_sz, hdr = struct.unpack_from('<IIIH', t, o)
        ncol, _fmt, _mips, ctype, itype, w, h = struct.unpack_from('<HBBBBHH', t, o + 14)
        img = t[o + hdr:o + hdr + img_sz]
        clut = t[o + hdr + img_sz:o + hdr + img_sz + clut_sz]
        cdepth = {1: 2, 2: 3, 3: 4}.get(ctype & 0x3f, 4)
        pal = [_colour(clut, i * cdepth, cdepth) for i in range(ncol)]
        if itype == 5 and not ctype & 0x80 and ncol == 256:
            # CSM1 palette order: entries 8-15 and 16-23 of every 32 swapped
            for blk in range(0, 256, 32):
                pal[blk + 8:blk + 16], pal[blk + 16:blk + 24] = \
                    pal[blk + 16:blk + 24], pal[blk + 8:blk + 16]
        if itype == 5:
            px = b''.join(pal[v] for v in img[:w * h])
        elif itype == 4:
            px = b''.join(pal[(img[i >> 1] >> 4) if i & 1 else (img[i >> 1] & 15)]
                          for i in range(w * h))
        elif itype in (1, 2, 3):
            d = {1: 2, 2: 3, 3: 4}[itype]
            px = b''.join(_colour(img, i * d, d) for i in range(w * h))
        else:
            raise ValueError('TIM2 image type %d' % itype)
        out.append((w, h, px))
        o += total
    return out


def png(w, h, rgba):
    raw = b''.join(b'\0' + rgba[y * w * 4:(y + 1) * w * 4] for y in range(h))

    def chunk(t, b):
        return (struct.pack('>I', len(b)) + t + b
                + struct.pack('>I', zlib.crc32(t + b) & 0xffffffff))
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


def elf_segments(elf):
    phoff, = struct.unpack_from('<I', elf, 0x1c)
    n, = struct.unpack_from('<H', elf, 0x2c)
    segs = []
    for i in range(n):
        t, off, va, _pa, fs, _ms = struct.unpack_from('<6I', elf, phoff + i * 32)
        if t == 1:
            segs.append((va, off, fs))
    return segs


def va_to_off(segs, va):
    for base, off, fs in segs:
        if base <= va < base + fs:
            return va - base + off
    raise ValueError('address %#x is not in the executable' % va)


def cstr(elf, off):
    return elf[off:elf.index(b'\0', off)].decode('latin-1')


# ── SuperNOVA ────────────────────────────────────────────────────────────────

class SuperNova:
    GAME = 'sn'
    ELF = 'SLUS_213.77'
    TABLE = 0x1a3a70            # file offset of the file table
    TABLE_COUNT = 1220
    TABLE_FIRST = 'LOGO/usn_klogocs.TM2c'
    SONGS = 0x1c1e10            # file offset of the song records, 0xa8 each

    # What the board draws with: output name -> archive entry.
    IMAGES = {
        'bg.png': 'ranking/ranking0000.TM2c',       # the globe behind the rankings
        'entry.png': 'ranking/n_entry0001.TM2c',    # the green name-entry tunnel
        'atlas.png': 'ranking/ranking00.CAP',       # the ranking screen's sprites
        'drum.png': 'ranking/AEPdrum0000.TM2c',     # the name-entry letters
        'ranktitle.png': 'ranking/usn_ranknm.TM2c',  # "Ranking" / "Internet Ranking"
        'panels.png': 'online/on_rank00.tm2c',      # the chamfered online panels
        'rankcol.png': 'online/on_rcob00.tm2c',     # the 1-10 rank column
        'digits.png': 'online/on_rank03.tm2c',      # orange digits and RANKING
        'labels.png': 'online/on_rsl00.tm2c',       # Match / Win / Lose / Draw
        'logo.png': 'LOGO/aepstart.CAP',            # the title screen's logo
        'lobby.png': 'online/ae/grandlobby.cap',    # the lobby menu's sprites
        'header.png': 'online/on_hham02.tm2c',      # the online screens' title strip
        'subtitle.png': 'online/on_subtitle.tm2c',  # "ONLINE PLAY"
        'side.png': 'mainmenu/usn_mmfr00.TM2c',     # the side strip with the game's name
        'frame.png': 'mainmenu/usn_mmfr01.TM2c',    # the menus' framed message panel
    }

    # Sprite rectangles, [file, x, y, w, h], measured on the decoded images.
    SPRITES = {
        'plate1': ['atlas.png', 0, 0, 67, 31],
        'plate2': ['atlas.png', 0, 32, 67, 31],
        'plate3': ['atlas.png', 0, 64, 67, 31],
        'plate': ['atlas.png', 0, 96, 67, 31],
        'ranking': ['ranktitle.png', 0, 2, 126, 20],
        'internet_ranking': ['ranktitle.png', 0, 26, 270, 20],
        'panel_orange': ['panels.png', 0, 0, 88, 48],
        'panel_green': ['panels.png', 88, 0, 88, 48],
        'logo': ['logo.png', 24, 117, 590, 217],
        'lobby_oval': ['lobby.png', 5, 0, 388, 86],
        'lobby_bar': ['lobby.png', 0, 91, 436, 37],
        'menu_rc': ['lobby.png', 0, 404, 300, 22],
        'menu_rc_dim': ['lobby.png', 0, 374, 300, 22],
        'header': ['header.png', 0, 0, 640, 38],
        'online_play': ['subtitle.png', 0, 0, 256, 20],
        'side': ['side.png', 0, 0, 34, 264],
        # the box only: the strip to its right is the menu's, not the panel's
        'frame': ['frame.png', 0, 0, 276, 214],
    }

    #: How the online screens are laid where the game has no picture for it:
    #: SuperNOVA's lobby is a plain navy screen (sampled from the game's own
    #: thumbnail of it, mainmenu/usn_mmthed), SuperNOVA 2 has a texture.
    THEME = {'online_bg': [[11, 18, 31], [30, 50, 88]], 'frame_edge': 12,
             'accent': 'yellow', 'brand': 'DDR SuperNOVA'}

    # Fonts: a grid of cells; each row string lists the cells left to right.
    FONTS = {
        'yellow': {'file': 'atlas.png', 'x': 68, 'y': 0, 'cw': 25, 'ch': 25,
                   'adv': 22, 'rows': ['ABCDEFGHIJKLM', 'NOPQRSTUVWXYZ',
                                       '0123456789:', '?!$&-.']},
        'teal': {'file': 'atlas.png', 'x': 68, 'y': 100, 'cw': 25, 'ch': 25,
                 'adv': 22, 'rows': ['ABCDEFGHIJKLM', 'NOPQRSTUVWXYZ',
                                     '0123456789:', '?!$&-.']},
        'white': {'file': 'atlas.png', 'x': 0, 'y': 204, 'cw': 16, 'ch': 24,
                  'adv': 15, 'rows': ['0123456789']},
        'drum': {'file': 'drum.png', 'x': 0, 'y': 0, 'cw': 48, 'ch': 28,
                 'adv': 40, 'rows': ['ABCDEFGHIJ', 'KLMNOPQRST', 'UVWXYZ',
                                     '0123456789', '?!$&-.']},
    }

    def __init__(self, f, files):
        self.f, self.files = f, files
        self.elf = read(f, files, self.ELF)
        self.segs = elf_segments(self.elf)
        self.table = self._table()
        self.image_base = files['DATA/IMAGE.DAT'][0]

    def _table(self):
        rows = {}
        for i in range(self.TABLE_COUNT):
            r = struct.unpack_from('<11I', self.elf, self.TABLE + i * 44)
            name = cstr(self.elf, va_to_off(self.segs, r[0]))
            rows[name.lower()] = (r[9], r[10])
            if i == 0 and name != self.TABLE_FIRST:
                raise ValueError('the file table is not where it was expected; '
                                 'is this the USA disc?')
        return rows

    def entry(self, name):
        size, sector = self.table[name.lower()]
        self.f.seek(self.image_base + sector * SECTOR)
        return tgcd(self.f.read(size))

    def picture(self, name):
        return tim2(self.entry(name))[0]

    def extra_pictures(self):
        return {}

    def sprites(self):
        return self.SPRITES

    def fonts(self, pictures):
        return {name: dict(font, glyphs=glyph_metrics(pictures[font['file']], font))
                for name, font in self.FONTS.items()}

    def songs(self):
        """{wire id: title}. A song record (0xa8 bytes) starts with its code,
        four or five characters, and carries its own 1-based index at +8,
        which is how the end of the array is found. Titles live elsewhere,
        as code NUL title NUL pairs. There is more than one such table and
        codes can be prefixes of each other (aaaa / aaaa2), so a code is
        matched whole, and a "title" that is itself code-shaped is the next
        code of a list that has no titles, not a title."""
        elf, off, out, i = self.elf, self.SONGS, {}, 0
        while struct.unpack_from('<H', elf, off + i * 0xa8 + 8)[0] == i + 1:
            code = elf[off + i * 0xa8:elf.index(b'\x00', off + i * 0xa8)]
            for m in re.finditer(rb'\x00' + re.escape(code)
                                 + rb'\x00([\x20-\x7e]+)\x00', elf):
                if not re.fullmatch(rb'[a-z0-9]{4,5}', m.group(1)):
                    out[str(i)] = m.group(1).decode('latin-1')
                    break
            i += 1
        return out


class SuperNova2(SuperNova):
    """SuperNOVA 2 is SuperNOVA's engine with the same archive, table and
    compression, and the same ranking screen art under the same names."""
    GAME = 'sn2'
    ELF = 'SLUS_216.08'
    TABLE = 0x1d6830
    TABLE_COUNT = 1281
    SONGS = 0x1f1ca0

    # It redrew its menus: chrome and cyan where SuperNOVA was orange, a
    # textured online background, its own logo.
    IMAGES = dict(SuperNova.IMAGES, **{
        'logo.png': 'LOGO/usn2_start_0.TM2c',
        'lobby.png': 'online/ae/AEPsn2_grandlobby.cap',
        'side.png': 'mainmenu/usn2_mmfr00.TM2c',
        'frame.png': 'mainmenu/usn2_mmfr01.TM2c',
        'onlinebg.png': 'online/on2_bg00.tm2c',
    })
    SPRITES = dict(SuperNova.SPRITES, **{
        'logo': ['logo.png', 2, 2, 516, 460],
        'menu_rc': ['lobby.png', 0, 404, 300, 24],
        'menu_rc_dim': ['lobby.png', 0, 374, 300, 24],
        'online_play': ['subtitle.png', 0, 0, 190, 20],
        'side': ['side.png', 0, 0, 8, 480],
        'frame': ['frame.png', 0, 0, 494, 52],
    })
    THEME = {'online_bg': 'onlinebg.png', 'frame_edge': 12, 'accent': 'teal',
             'brand': 'DDR SuperNOVA 2'}


# ── Extreme 2 ────────────────────────────────────────────────────────────────

def klz(d, pos=0):
    """Konami LZ, the Extreme 2 compression. (output, end position)."""
    out = bytearray()
    n = len(d)
    while pos < n:
        ctrl = d[pos]
        pos += 1
        for _ in range(8):
            if not ctrl & 1:
                out.append(d[pos])
                pos += 1
            else:
                t = d[pos]
                pos += 1
                if t == 0xff:
                    return bytes(out), pos
                if t >= 0xc0:
                    ln = (t & 0x3f) + 8
                    out += d[pos:pos + ln]
                    pos += ln
                    ctrl >>= 1
                    continue
                if t < 0x80:
                    ln, dist = (t >> 2) + 3, ((t & 3) << 8) | d[pos]
                    pos += 1
                else:
                    ln, dist = ((t >> 4) & 3) + 2, (t & 15) + 1
                src = len(out) - dist
                if src < 0:
                    raise ValueError('LZ distance before the start')
                for k in range(ln):
                    out.append(out[src + k])
            ctrl >>= 1
    raise ValueError('LZ stream has no end marker')


def _members(b):
    """The members of a package, or None if `b` is not one. Two shapes:
    (offset, size) pairs whose first offset is the table's own size, or a
    list of increasing offsets (the last member runs to the end)."""
    if len(b) < 16:
        return None
    h, = struct.unpack_from('<I', b, 0)
    if 8 <= h <= min(len(b), 0x10000) and h % 8 == 0:
        w = struct.unpack_from('<%dI' % (h // 4), b, 0)
        pairs, last, ok = [], None, True
        for k in range(0, len(w), 2):
            off, size = w[k], w[k + 1]
            if off == 0 and size == 0:
                pairs.append(None)
                continue
            if (off + size > len(b) or size == 0
                    or (last is None and off != h)
                    or (last is not None and not 0 <= off - last < 0x800)):
                ok = False
                break
            pairs.append(b[off:off + size])
            last = off + size
        if ok and any(pairs):
            return pairs
    if 8 <= h <= min(len(b), 0x10000) and h % 4 == 0:
        w = struct.unpack_from('<%dI' % (h // 4), b, 0)
        if all(w[k] <= w[k + 1] for k in range(len(w) - 1)) and w[-1] <= len(b):
            spans = [b[w[k]:w[k + 1]] for k in range(len(w) - 1)]
            if any(b[w[-1]:]):
                spans.append(b[w[-1]:])
            return spans
    return None


def tcb(b):
    """The first picture of a TCB texture: (w, h, rgba)."""
    if b[:4] != b'TCB\0':
        raise ValueError('not a TCB (%r)' % b[:4])
    _tot, palsz, imgsz, imgoff, _ncol, _u, psm, w, h = \
        struct.unpack_from('<IIIHHHHHH', b, 0x10)
    img = b[0x20 + imgoff:0x10 + imgoff + imgsz]
    pal = b[0x20 + imgoff + imgsz:0x10 + imgoff + imgsz + palsz]
    cols = [_colour(pal, i * 4, 4) for i in range(len(pal) // 4)]
    for blk in range(0, len(cols) - len(cols) % 32, 32):
        cols[blk + 8:blk + 16], cols[blk + 16:blk + 24] = \
            cols[blk + 16:blk + 24], cols[blk + 8:blk + 16]
    cols += [b'\0\0\0\0'] * (256 - len(cols))
    if psm == 5:
        px = b''.join(cols[v] for v in img[:w * h])
    elif psm == 4:
        px = b''.join(cols[(img[i >> 1] >> 4) if i & 1 else (img[i >> 1] & 15)]
                      for i in range(w * h))
    else:
        raise ValueError('TCB pixel format %d' % psm)
    return w, h, px


class Extreme2:
    GAME = 'e2'
    ELF = 'SLUS_211.74'
    TABLE = 0x20cfe8            # file offset of the u64 file table
    LSN_BASE = 4000             # its sectors count from FILEDATA.BIN
    PERM = 0x2e7850             # u16[74]: wire song id -> internal song id
    SONGS = 0x1d7e90            # file offset of the song records, 0xa0 each
    BANNERS = 4332              # each internal song's 224x32 banner
    SONG_COUNT = 74

    # Output name -> entry path: a table id, then a member index per level
    # of package (an LZ stream is unpacked in place, not a level of its own).
    # None of it has a name on the disc; these were identified by eye.
    IMAGES = {
        'bg.png': '4363/2',       # the blue crystal background
        'frame.png': '4380/7',    # the chrome "C" frame and its LCD bar
        'side.png': '4329/5',     # the teal curved side panel
        'bars.png': '4381/20',    # the dark and grey row bars
        'badges.png': '4381/8',   # rank badges 1-10
        'buttons.png': '4381/12',  # HEAD-TO-HEAD, RANKING CHALLENGE, ...
        'digits.png': '4381/16',  # the outlined score digits
        'rcbanner.png': '4381/10',  # the RANKING CHALLENGE banner
        'weeks.png': '4381/4',    # WEEKS FROM BEGINNING / UNTIL THE END
        'labels.png': '4381/19',  # POINT, HEAD-TO-HEAD, WIN, LOSS, ...
        'online.png': '4379/0',   # ONLINE PLAY
        'logo.png': '4381/27',    # the DDR Extreme 2 logo
        'font.png': '4322',         # the system font
    }

    SPRITES = dict({
        'badge%d' % k: ['badges.png', 0 if k <= 5 else 30, (k - 1) % 5 * 30, 30, 30]
        for k in range(1, 11)}, **{
        'frame': ['frame.png', 0, 0, 400, 416],
        'tab_h2h': ['buttons.png', 0, 0, 129, 32],
        'tab_rc': ['buttons.png', 0, 36, 176, 32],
        'bar_dark': ['bars.png', 0, 0, 290, 24],
        'bar_grey': ['bars.png', 0, 24, 290, 24],
        'rc_banner': ['rcbanner.png', 0, 0, 256, 80],
        'until_end': ['weeks.png', 0, 19, 120, 16],
        'weeks_bar': ['weeks.png', 0, 36, 286, 36],
        'point': ['labels.png', 0, 1, 70, 16],
        'head_to_head': ['labels.png', 0, 18, 170, 16],
        'this_week': ['labels.png', 0, 34, 150, 16],
        'total_ranking': ['labels.png', 0, 50, 116, 16],
        'win': ['labels.png', 0, 98, 32, 16],
        'loss': ['labels.png', 0, 114, 42, 16],
        'draw': ['labels.png', 0, 130, 46, 16],
        'online_play': ['online.png', 0, 0, 176, 18],
        'logo': ['logo.png', 30, 20, 590, 346],      # the logo, not its copyright line
    })

    # The score digits, as measured: the ink of each glyph, plus its outline.
    DIGITS = ('0123456789.,:/', [
        (4, 22), (34, 42), (56, 74), (81, 99), (108, 126), (134, 152),
        (159, 177), (187, 203), (211, 229), (238, 256), (263, 266),
        (274, 276), (285, 287), (295, 302)])

    def __init__(self, f, files):
        self.f, self.files = f, files
        self.elf = read(f, files, self.ELF)
        self.segs = elf_segments(self.elf)
        self.table = {}
        o = self.TABLE
        while True:
            q, = struct.unpack_from('<Q', self.elf, o)
            if q & 0xffff == 0xffff:
                break
            self.table[q & 0xffff] = ((q >> 16) & 0xffffff, q >> 40)
            o += 8
        if self.BANNERS not in self.table:
            raise ValueError('the file table is not where it was expected; '
                             'is this the USA disc?')
        po = va_to_off(self.segs, self.PERM)
        self.perm = list(struct.unpack_from('<%dH' % self.SONG_COUNT, self.elf, po))
        if sorted(self.perm) != list(range(self.SONG_COUNT)):
            raise ValueError('the song order table is not where it was expected')

    def entry(self, eid):
        lsn, sectors = self.table[eid]
        self.f.seek((lsn + self.LSN_BASE) * SECTOR)
        return self.f.read(sectors * SECTOR)

    @staticmethod
    def unpack(b):
        """A blob as stored: an LZ stream (it starts with a control byte and
        then "TCB", or decodes cleanly) is decompressed, anything else kept."""
        if b[1:4] == b'TCB' or (b[:4] != b'TCB\0' and _members(b) is None):
            try:
                return klz(b)[0]
            except (ValueError, IndexError):
                pass
        return b

    def get(self, path):
        parts = [int(x) for x in path.split('/')]
        b = self.unpack(self.entry(parts[0]))
        for p in parts[1:]:
            members = _members(b)
            if members is None:
                raise ValueError('%s: not a package at %d' % (path, p))
            b = self.unpack(members[p])
        return b

    def picture(self, path):
        return tcb(self.get(path))

    def extra_pictures(self):
        """Every song's Ranking Challenge banner, stacked in internal order."""
        members = _members(self.unpack(self.entry(self.BANNERS)))
        px = bytearray()
        for i in range(self.SONG_COUNT):
            inner = _members(members[i])
            w, h, p = tcb(self.unpack(inner[0] if inner else members[i]))
            if (w, h) != (224, 32):
                raise ValueError('banner %d is %dx%d' % (i, w, h))
            px += p
        return {'banners.png': (224, 32 * self.SONG_COUNT, bytes(px))}

    def sprites(self):
        out = dict(self.SPRITES)
        for wire, internal in enumerate(self.perm):
            out['song%d' % wire] = ['banners.png', 0, internal * 32, 224, 32]
        return out

    def fonts(self, pictures):
        w, _h, px = pictures['font.png']

        def ink(x, y):
            i = (y * w + x) * 4
            return px[i + 3] > 160 and max(px[i:i + 3]) > 160
        glyphs = {}
        for r in range(6):                  # printable ASCII, 16 a row
            want = [chr(c) for c in range(0x20 + 16 * r, 0x30 + 16 * r)
                    if chr(c) not in ' \x7f']
            cols = [any(ink(x, y) for y in range(r * 24, r * 24 + 24))
                    for x in range(w)] + [False]
            segs, start = [], None
            for x, c in enumerate(cols):
                if c and start is None:
                    start = x
                if not c and start is not None:
                    segs.append([start, x])
                    start = None
            while len(segs) > len(want):    # '"' is two marks: rejoin it
                gaps = [segs[i + 1][0] - segs[i][1] for i in range(len(segs) - 1)]
                i = gaps.index(min(gaps))
                segs[i:i + 2] = [[segs[i][0], segs[i + 1][1]]]
            if len(segs) != len(want):
                raise ValueError('font row %d: %d glyphs, expected %d'
                                 % (r, len(segs), len(want)))
            for ch, (a, b) in zip(want, segs):
                glyphs[ch] = [max(0, a - 2), r * 24, b - a + 4]
        chars, spans = self.DIGITS
        digits = {ch: [a - 2, 0, b - a + 4] for ch, (a, b) in zip(chars, spans)}
        return {'sys': {'file': 'font.png', 'ch': 24, 'adv': 10, 'glyphs': glyphs},
                'digits': {'file': 'digits.png', 'ch': 28, 'adv': 21,
                           'glyphs': digits}}

    def songs(self):
        """{wire id: title}: through the order table to the internal record,
        whose code leads it, and from the code to its title."""
        elf, out = self.elf, {}
        for wire, internal in enumerate(self.perm):
            o = self.SONGS + internal * 0xa0
            code = elf[o:elf.index(b'\x00', o)]
            for m in re.finditer(rb'\x00' + re.escape(code)
                                 + rb'\x00+([\x20-\x7e]+)\x00', elf):
                if not re.fullmatch(rb'[a-z0-9]{4,5}', m.group(1)):
                    out[str(wire)] = m.group(1).decode('latin-1')
                    break
        return out


GAMES = {'SLUS-21377': SuperNova, 'SLUS-21608': SuperNova2,
         'SLUS-21174': Extreme2}


def glyph_metrics(picture, font):
    """{char: [x, y, w]}: where each glyph's ink starts and how wide it is,
    so text can be set proportionally the way the game's menus set it,
    instead of every letter taking a whole cell."""
    w, _h, px = picture
    out = {}
    for r, row in enumerate(font['rows']):
        for c, ch in enumerate(row):
            x0, y0 = font['x'] + c * font['cw'], font['y'] + r * font['ch']
            ink = [x for x in range(font['cw'])
                   if any(px[((y0 + y) * w + x0 + x) * 4 + 3] > 64
                          for y in range(font['ch']))]
            if ink:
                out[ch] = [x0 + ink[0], y0, ink[-1] - ink[0] + 1]
    return out


def bake(path, out_root):
    with open(path, 'rb') as f:
        files = iso_files(f)
        if 'SYSTEM.CNF' not in files:
            print('%s: not a PS2 disc, skipped' % path)
            return None
        ser = serial(f, files)
        cls = GAMES.get(ser)
        if cls is None:
            print('%s: %s is not a disc the boards know, skipped' % (path, ser))
            return None
        game = cls(f, files)
        out = os.path.join(out_root, cls.GAME)
        os.makedirs(out, exist_ok=True)
        pictures = {fname: game.picture(src) for fname, src in cls.IMAGES.items()}
        pictures.update(game.extra_pictures())
        for fname, (w, h, px) in pictures.items():
            with open(os.path.join(out, fname), 'wb') as fh:
                fh.write(png(w, h, px))
        index = {'game': cls.GAME, 'serial': ser, 'files': sorted(pictures),
                 'theme': getattr(cls, 'THEME', {}),
                 'sprites': game.sprites(), 'fonts': game.fonts(pictures),
                 'songs': game.songs()}
        tmp = os.path.join(out, 'board.json.tmp')
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(index, fh, indent=1)
        os.replace(tmp, os.path.join(out, 'board.json'))
        print('%s: %s baked into %s (%d images, %d song titles)'
              % (path, ser, out, len(pictures), len(index['songs'])))
        return out


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('discs', nargs='+', help='disc images (.iso)')
    ap.add_argument('--out', default=os.path.join(
        os.environ.get('DDR_STATE_DIR', '/state'), 'boardart'),
        help='where to write the art (default /state/boardart)')
    args = ap.parse_args(argv)
    done = 0
    for p in args.discs:
        try:
            done += bake(p, args.out) is not None
        except (OSError, ValueError, KeyError) as e:
            print('%s: could not bake (%s)' % (p, e))
    if not done:
        sys.exit('nothing baked')


if __name__ == '__main__':
    main()
