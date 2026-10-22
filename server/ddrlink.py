"""The account link: lets a website prove a DDR login belongs to someone.

An OpenLobby website (or anything else that speaks gamelink.py's small signed
API) can link a player's website account to their DDR login, and let them set
a new DDR password from the website. Off unless GAMELINK_SECRET is set.

A DDR login never reaches the gate in the clear. The client builds the 0x3003
body as

    name[32] (zero-padded) + MD5(name + challenge + password)    challenge = 16 zero bytes

and enciphers the packet with Blowfish-ECB (big-endian 32-bit halves) under
one 56-byte key the three games share. The gate keeps what it receives:
credentials.username = hex(E(name[32]) with trailing NULs cut) and
credentials.digest = hex(E(MD5(...))). So checking a password typed on a
website means computing those two values from it, which needs the key.

The key is on the disc, not in this repository: tools/loginkey.py copies it
from your own disc into loginkey.bin in the state folder (or the file named by
DDR_LOGIN_KEY_FILE), and the link refuses to start without it.

    POST /v1/verify        {"account", "password"} -> {"ok": true, "account", "key"}
    POST /v1/set-password  {"account", "password"} -> {"ok": true, "account", "key"}

`key` is the stored login name, the stable id the website keeps the link by.
"""
import binascii
import hashlib
import os
import struct

import db
import gamelink

#: E(8 zero bytes) under the right key: the block every short name's zero
#: padding enciphers to, so a key can be checked without being known.
KEY_CHECK = bytes.fromhex('6566f6e5302aaa4c')

_N_WORDS = 18 + 4 * 256
_M32 = 0xFFFFFFFF


def _pi_words(n):
    """The first n 32-bit words of pi's fractional hex digits, which are
    Blowfish's initial P-array and S-boxes (Machin's formula)."""
    bits = n * 32
    guard = 64
    one = 1 << (bits + guard)

    def arctan_inv(x):
        x2 = x * x
        term = one // x
        total, k, sign = term, 1, -1
        while term:
            term //= x2
            k += 2
            total += sign * (term // k)
            sign = -sign
        return total

    pi = 4 * (4 * arctan_inv(5) - arctan_inv(239))
    frac = (pi - 3 * one) >> guard
    return [(frac >> (bits - 32 * (i + 1))) & _M32 for i in range(n)]


_PI = None


class Blowfish:
    """Plain Blowfish-ECB, standard library only."""

    def __init__(self, key):
        global _PI
        if _PI is None:
            _PI = _pi_words(_N_WORDS)
        self.P = _PI[:18]
        self.S = [_PI[18 + 256 * i:18 + 256 * (i + 1)] for i in range(4)]
        k = len(key)
        j = 0
        for i in range(18):
            d = 0
            for _ in range(4):
                d = (d << 8) | key[j]
                j = (j + 1) % k
            self.P[i] ^= d
        left = right = 0
        for i in range(0, 18, 2):
            left, right = self._enc(left, right)
            self.P[i], self.P[i + 1] = left, right
        for box in self.S:
            for i in range(0, 256, 2):
                left, right = self._enc(left, right)
                box[i], box[i + 1] = left, right

    def _f(self, x):
        s = self.S
        h = (s[0][x >> 24] + s[1][(x >> 16) & 0xFF]) & _M32
        return ((h ^ s[2][(x >> 8) & 0xFF]) + s[3][x & 0xFF]) & _M32

    def _enc(self, left, right):
        p = self.P
        for i in range(16):
            left ^= p[i]
            right ^= self._f(left)
            left, right = right, left
        left, right = right, left
        return left ^ p[17], right ^ p[16]

    def encrypt(self, data):
        if len(data) % 8:
            raise ValueError('Blowfish-ECB needs a multiple of 8 bytes')
        out = bytearray()
        for i in range(0, len(data), 8):
            left, right = struct.unpack('>II', data[i:i + 8])
            out += struct.pack('>II', *self._enc(left, right))
        return bytes(out)


def key_ok(key):
    """Whether `key` is the games' login key."""
    return len(key) == 56 and Blowfish(key).encrypt(bytes(8)) == KEY_CHECK


_cipher = None


def wire_name(name):
    """credentials.username for a name as typed."""
    raw = name.encode('latin-1')[:32]
    return binascii.hexlify(
        _cipher.encrypt(raw.ljust(32, b'\0')).rstrip(b'\0')).decode()


def wire_digest(name, password):
    md = hashlib.md5(name.encode('latin-1') + bytes(16)
                     + password.encode('latin-1')).digest()
    return binascii.hexlify(_cipher.encrypt(md)).decode()


def _stored(name):
    """(the spelling that matched, credentials.username, stored digest), or
    None. Names are tried as typed and upper-cased, since the game's name
    entry is upper case."""
    for n in dict.fromkeys((name, name.upper())):
        try:
            u = wire_name(n)
        except UnicodeEncodeError:
            return None
        with db._lock:
            row = db._conn.execute(
                'SELECT digest FROM credentials WHERE username=?', (u,)).fetchone()
        if row is not None:
            return n, u, row[0]
    return None


def link_verify(req):
    name, pw = str(req.get('account', '')).strip(), str(req.get('password', ''))
    if not name or len(name) > 32:
        return {'ok': False, 'error': 'no_account'}
    hit = _stored(name)
    if hit is None:
        return {'ok': False, 'error': 'no_account'}
    n, u, digest = hit
    try:
        if wire_digest(n, pw) != digest:
            return {'ok': False, 'error': 'bad_password'}
    except UnicodeEncodeError:
        return {'ok': False, 'error': 'bad_password'}
    return {'ok': True, 'account': n, 'key': u}


def link_set_password(req):
    """1 to 32 printable ASCII characters and no spaces: the client refuses a
    longer password."""
    pw = str(req.get('password', ''))
    if not (1 <= len(pw) <= 32 and pw.isascii() and pw.isprintable()
            and ' ' not in pw):
        return {'ok': False, 'error': 'bad_new_password'}
    hit = _stored(str(req.get('account', '')).strip())
    if hit is None:
        return {'ok': False, 'error': 'no_account'}
    n, u, _ = hit
    db.credential_set(u, wire_digest(n, pw), source='website')
    return {'ok': True, 'account': n, 'key': u}


def start(state_dir, log=print):
    """Load the key and start the API on loopback. None when it cannot run."""
    global _cipher
    path = os.environ.get('DDR_LOGIN_KEY_FILE') or os.path.join(state_dir,
                                                                'loginkey.bin')
    try:
        with open(path, 'rb') as f:
            key = f.read()
    except OSError:
        log('account link: no %s; make it with tools/loginkey.py' % path)
        return None
    if not key_ok(key):
        log('account link: %s is not the login key' % path)
        return None
    _cipher = Blowfish(key)
    return gamelink.serve({'/v1/verify': link_verify,
                           '/v1/set-password': link_set_password},
                          int(os.environ.get('DDR_LINK_PORT', '19590')), log=log)
