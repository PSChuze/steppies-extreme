#!/usr/bin/env python3
"""Draw board images from the baked art.

Every screen a board shows, on its page and in Discord, is a picture
composited here from the game's sprites and fonts. Standard library only, so
it is deliberately small: decode the PNGs boardart.py wrote, blit sprites with
alpha, draw text a glyph at a time from a font grid, and encode the result.
"""
import os
import struct
import zlib


def read_png(blob):
    """(w, h, bytearray rgba) for an 8-bit RGB or RGBA, non-interlaced PNG,
    which is everything boardart.py writes."""
    if blob[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('not a PNG')
    i, idat = 8, b''
    w = h = ctype = None
    while i < len(blob):
        n, t = struct.unpack_from('>I4s', blob, i)
        body = blob[i + 8:i + 8 + n]
        if t == b'IHDR':
            w, h, _depth, ctype = struct.unpack_from('>IIBB', body)
        elif t == b'IDAT':
            idat += body
        i += 12 + n
    bpp = {6: 4, 2: 3}[ctype]
    raw = zlib.decompress(idat)
    stride = w * bpp
    out = bytearray()
    prev = bytearray(stride)
    p = 0
    for _ in range(h):
        f = raw[p]
        line = bytearray(raw[p + 1:p + 1 + stride])
        p += 1 + stride
        if f:
            for x in range(stride):
                a = line[x - bpp] if x >= bpp else 0
                b = prev[x]
                c = prev[x - bpp] if x >= bpp else 0
                if f == 1:
                    line[x] = (line[x] + a) & 255
                elif f == 2:
                    line[x] = (line[x] + b) & 255
                elif f == 3:
                    line[x] = (line[x] + (a + b) // 2) & 255
                else:
                    pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                    line[x] = (line[x] + (a if pa <= pb and pa <= pc
                                          else b if pb <= pc else c)) & 255
        if bpp == 4:
            out += line
        else:
            for k in range(0, stride, 3):
                out += line[k:k + 3] + b'\xff'
        prev = line
    return w, h, out


def write_png(w, h, rgba):
    raw = b''.join(b'\0' + bytes(rgba[y * w * 4:(y + 1) * w * 4]) for y in range(h))

    def chunk(t, b):
        return (struct.pack('>I', len(b)) + t + b
                + struct.pack('>I', zlib.crc32(t + b) & 0xffffffff))
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 6)) + chunk(b'IEND', b''))


# Marks most game fonts lack, dropped outright when a font has no glyph for
# them: drawn as a space, "WON'T" reads as "WON T".
DROP = "'\"`"


class Canvas:
    def __init__(self, w, h, rgb=(0, 0, 0), transparent=False):
        """A w x h picture, filled with `rgb`, or with nothing at all when
        `transparent` (a sprite or a word for the page, which sits on the
        game's own backdrop rather than on a black box)."""
        self.w, self.h = w, h
        self.transparent = transparent
        self.px = bytearray(bytes(rgb) + (b'\x00' if transparent else b'\xff')) * (w * h)

    @classmethod
    def from_image(cls, img):
        """A canvas that starts as a copy of `img`, alpha ignored: the fast
        way to lay a background, which a per-pixel blit would crawl over."""
        c = cls.__new__(cls)
        c.transparent = False
        c.w, c.h, px = img
        c.px = bytearray(px)
        c.px[3::4] = b'\xff' * (c.w * c.h)
        return c

    def blit(self, img, sx, sy, sw, sh, dx, dy, alpha=255):
        """Copy the (sx, sy, sw, sh) part of `img` to (dx, dy), blended by
        its alpha (times `alpha`/255)."""
        iw, ih, src = img
        sw, sh = min(sw, iw - sx), min(sh, ih - sy)     # never read past the art
        dst = self.px
        for y in range(sh):
            ty = dy + y
            if not 0 <= ty < self.h:
                continue
            for x in range(sw):
                tx = dx + x
                if not 0 <= tx < self.w:
                    continue
                s = ((sy + y) * iw + sx + x) * 4
                a = src[s + 3] * alpha // 255
                if not a:
                    continue
                d = (ty * self.w + tx) * 4
                if a == 255:
                    dst[d:d + 3] = src[s:s + 3]
                    dst[d + 3] = 255
                elif self.transparent:
                    # "over" onto a picture that may itself be see-through
                    da = dst[d + 3]
                    oa = a + da * (255 - a) // 255
                    for k in range(3):
                        dst[d + k] = (src[s + k] * a + dst[d + k] * da * (255 - a) // 255) // oa
                    dst[d + 3] = oa
                else:
                    for k in range(3):
                        dst[d + k] = (src[s + k] * a + dst[d + k] * (255 - a)) // 255

    def crop(self, h):
        """Keep the top h rows."""
        self.px = self.px[:self.w * h * 4]
        self.h = h
        return self

    def gradient(self, top, bottom):
        """Fill top to bottom from one colour to another: the plain screen a
        game's own panels sit on where the game has no texture for it."""
        for y in range(self.h):
            t = y / max(1, self.h - 1)
            row = bytes(int(a + (b - a) * t) for a, b in zip(top, bottom)) + bytes((255,))
            self.px[y * self.w * 4:(y + 1) * self.w * 4] = row * self.w

    def png(self):
        return write_png(self.w, self.h, self.px)


class Art:
    """The baked art of one game: images by file name, plus board.json."""

    def __init__(self, art_dir, index):
        self.dir, self.index = art_dir, index
        self._img = {}

    def image(self, name):
        if name not in self._img:
            with open(os.path.join(self.dir, name), 'rb') as fh:
                self._img[name] = read_png(fh.read())
        return self._img[name]

    def sprite(self, canvas, name, x, y, alpha=255, w=None, h=None):
        """Draw a sprite at (x, y), at its own size or scaled to w x h (give
        one and the other keeps the aspect). Returns the size drawn."""
        f, sx, sy, sw, sh = self.index['sprites'][name]
        if w is None and h is None:
            canvas.blit(self.image(f), sx, sy, sw, sh, x, y, alpha)
            return sw, sh
        w = w or max(1, round(sw * h / sh))
        h = h or max(1, round(sh * w / sw))
        img = self.scaled(name, w, h)
        canvas.blit(img, 0, 0, w, h, x, y, alpha)
        return w, h

    def scaled(self, name, w, h):
        """A sprite resized to w x h; see scaled_rect."""
        return self.scaled_rect(*self.index['sprites'][name], w, h)

    def scaled_rect(self, f, sx, sy, sw, sh, w, h):
        """The (sx, sy, sw, sh) part of file `f` resized to w x h by
        averaging the source pixels each target pixel covers (alpha-weighted,
        so edges do not darken). Logos are drawn far smaller than their art,
        which nearest-neighbour would turn to noise. Cached: the boards draw
        the same sizes every time."""
        key = ('scaled', f, sx, sy, sw, sh, w, h)
        if key in self._img:
            return self._img[key]
        iw, _ih, src = self.image(f)
        out = bytearray(w * h * 4)
        for ty in range(h):
            y0, y1 = sy + ty * sh // h, sy + max(ty * sh // h + 1, (ty + 1) * sh // h)
            for tx in range(w):
                x0, x1 = sx + tx * sw // w, sx + max(tx * sw // w + 1, (tx + 1) * sw // w)
                r = g = b = a = n = 0
                for yy in range(y0, y1):
                    o = (yy * iw + x0) * 4
                    for _ in range(x0, x1):
                        pa = src[o + 3]
                        r += src[o] * pa
                        g += src[o + 1] * pa
                        b += src[o + 2] * pa
                        a += pa
                        n += 1
                        o += 4
                d = (ty * w + tx) * 4
                if a:
                    out[d:d + 4] = bytes((r // a, g // a, b // a, a // n))
        self._img[key] = (w, h, bytes(out))
        return self._img[key]

    def panel(self, canvas, name, x, y, w, h, edge):
        """A framed panel stretched to w x h without stretching its frame:
        the sprite's corners (edge pixels square) are drawn as they are, its
        edges repeat along their length, and its middle fills the rest."""
        f, sx, sy, sw, sh = self.index['sprites'][name]
        img = self.image(f)
        e = edge
        mw, mh = sw - 2 * e, sh - 2 * e
        # corners
        for cx, cy, dx, dy in ((0, 0, 0, 0), (sw - e, 0, w - e, 0),
                               (0, sh - e, 0, h - e), (sw - e, sh - e, w - e, h - e)):
            canvas.blit(img, sx + cx, sy + cy, e, e, x + dx, y + dy)
        # edges, tiled
        for off in range(e, w - e, mw):
            n = min(mw, w - e - off)
            canvas.blit(img, sx + e, sy, n, e, x + off, y)
            canvas.blit(img, sx + e, sy + sh - e, n, e, x + off, y + h - e)
        for off in range(e, h - e, mh):
            n = min(mh, h - e - off)
            canvas.blit(img, sx, sy + e, e, n, x, y + off)
            canvas.blit(img, sx + sw - e, sy + e, e, n, x + w - e, y + off)
        # middle, tiled
        for oy in range(e, h - e, mh):
            for ox in range(e, w - e, mw):
                canvas.blit(img, sx + e, sy + e, min(mw, w - e - ox), min(mh, h - e - oy),
                            x + ox, y + oy)

    def _layout(self, font_name, text, mono):
        """[(glyph or None, x offset)] and the total width. Proportional text
        is set from each glyph's measured ink plus a two-pixel gap; monospace
        (scores, so columns line up) uses the font's advance."""
        font = self.index['fonts'][font_name]
        glyphs = font.get('glyphs') or {}
        out, x = [], 0
        for ch in str(text):
            # a font without lowercase (most of them) sets it as capitals
            if ch not in glyphs:
                ch = ch.upper()
            if ch not in glyphs and ch in DROP:
                continue
            g = glyphs.get(ch)
            if mono or not glyphs:
                out.append((g, x + ((font['adv'] - g[2]) // 2 if g else 0)))
                x += font['adv']
            elif g is None:
                x += font['adv'] // 2          # space, or a letter it lacks
            else:
                out.append((g, x))
                x += g[2] + 2
        return out, x

    def text_width(self, font_name, text, mono=False, scale=1.0):
        return round(self._layout(font_name, text, mono)[1] * scale)

    def text(self, canvas, font_name, text, x, y, right=False, maxw=None,
             mono=False, scale=1.0, center=False):
        """Draw `text` in a game font and return its width. `maxw` cuts it to
        fit, the way the game cuts a long name; `scale` draws it smaller,
        each glyph averaged down rather than squashed."""
        font = self.index['fonts'][font_name]
        text = str(text)
        while maxw is not None and text and \
                self.text_width(font_name, text, mono, scale) > maxw:
            text = text[:-1]
        laid, w = self._layout(font_name, text, mono)
        w = round(w * scale)
        if right:
            x -= w
        elif center:
            x -= w // 2
        img = self.image(font['file'])
        for g, off in laid:
            if g is None:
                continue
            if scale == 1.0:
                canvas.blit(img, g[0], g[1], g[2], font['ch'], x + off, y)
            else:
                gw, gh = max(1, round(g[2] * scale)), max(1, round(font['ch'] * scale))
                canvas.blit(self.scaled_rect(font['file'], g[0], g[1], g[2], font['ch'],
                                             gw, gh), 0, 0, gw, gh, x + round(off * scale), y)
        return w

    def fit_text(self, canvas, font_name, text, x, y, room, least=0.7, **kw):
        """Draw `text` shrunk until it fits `room` (down to `least`), then
        cut. For names beside something that must stay readable."""
        full = self.text_width(font_name, text, kw.get('mono', False))
        k = max(least, min(1.0, room / full)) if full else 1.0
        return self.text(canvas, font_name, text, x, y + round((1 - k) * 12),
                         maxw=room, scale=k, **kw)
