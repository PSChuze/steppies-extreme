#!/usr/bin/env python3
"""Discord bot credentials from an external bot registry.

Optional. A server that runs beside a larger stack with its own admin page
for Discord bots can keep its board bots' tokens there, with every other
bot's. That page stores them in the Postgres table discord_bot, the token
sealed with POL_BOT_KEY. This module reads them, standard library only:

    POL_DATABASE_URL   postgresql://user:password@host:port/database
    POL_BOT_KEY        the key the admin page seals tokens with
    POL_VALKEY_URL     valkey://host:port/db, to report back which
                       credentials a board runs on (optional)
    POL_KV_PREFIX      the key prefix there, "pol:" by default
    POL_BOT_RELOAD_EVERY  seconds between checks for a changed row (60)

Without POL_DATABASE_URL nothing here runs and the boards use their own
environment, as they always did.

It only ever reads discord_bot. The one thing it writes is
botcreds:applied:<name> in Valkey, which is how the admin page shows that a
bot is live and where its token came from. The sealing and the table belong
to the admin page; this is a reader for that format, kept dependency-free, so
it carries its own tiny Postgres and RESP clients rather than a driver.

The seal: the key is sha256(POL_BOT_KEY); a stored token is
"b1:" + base64(nonce[16] + ciphertext + tag[16]), the ciphertext XORed with an
HMAC-SHA256 keystream and the tag the first 16 bytes of an HMAC over the nonce
and ciphertext.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import sys
import threading
import time
import urllib.parse

SEAL_VER = 'b1'


def log(text):
    print('[polregistry] %s' % text, file=sys.stderr, flush=True)


def enabled():
    return bool(os.environ.get('POL_DATABASE_URL', '').strip())


# ── the seal ─────────────────────────────────────────────────────────────────

def _key():
    raw = os.environ.get('POL_BOT_KEY', '').strip()
    return hashlib.sha256(raw.encode('utf-8')).digest() if raw else None


def _stream(key, nonce, n):
    out, ctr = b'', 0
    while len(out) < n:
        out += hmac.new(key, b'stream' + nonce + ctr.to_bytes(4, 'big'),
                        hashlib.sha256).digest()
        ctr += 1
    return out[:n]


def unseal(sealed):
    """The token, or '' when there is none, no key, or it was sealed under
    another key or tampered with."""
    key = _key()
    if not sealed or key is None or not sealed.startswith(SEAL_VER + ':'):
        return ''
    try:
        raw = base64.b64decode(sealed[len(SEAL_VER) + 1:])
    except (ValueError, binascii.Error):
        return ''
    if len(raw) < 32:
        return ''
    nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
    want = hmac.new(key, b'tag' + nonce + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, want):
        return ''
    return bytes(a ^ b for a, b in zip(ct, _stream(key, nonce, len(ct)))).decode(
        'utf-8', 'replace')


def seal(token):
    """The admin page's half, here only so the tests can make a row."""
    key = _key()
    raw = token.encode('utf-8')
    nonce = secrets.token_bytes(16)
    ct = bytes(a ^ b for a, b in zip(raw, _stream(key, nonce, len(raw))))
    tag = hmac.new(key, b'tag' + nonce + ct, hashlib.sha256).digest()[:16]
    return SEAL_VER + ':' + base64.b64encode(nonce + ct + tag).decode('ascii')


# ── a minimal Postgres client: connect, authenticate, simple query ───────────

class PgError(Exception):
    pass


class Postgres:
    """Just enough of the frontend/backend protocol (v3) to run a SELECT:
    startup, password authentication (cleartext, MD5 or SCRAM-SHA-256, which
    is what a stock Postgres asks for), and the simple query protocol. Every
    value comes back as text, which is all a credentials row needs."""

    def __init__(self, url, timeout=10.0):
        u = urllib.parse.urlparse(url)
        if u.scheme not in ('postgres', 'postgresql'):
            raise PgError('not a postgres URL')
        self.user = urllib.parse.unquote(u.username or '')
        self.password = urllib.parse.unquote(u.password or '')
        self.database = (u.path or '/').lstrip('/') or self.user
        self.sock = socket.create_connection((u.hostname or '127.0.0.1', u.port or 5432),
                                             timeout=timeout)
        self.buf = b''
        try:
            self._startup()
        except Exception:
            self.close()
            raise

    def close(self):
        try:
            self.sock.sendall(b'X' + struct.pack('>I', 4))
        except OSError:
            pass
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _send(self, kind, body):
        self.sock.sendall(kind + struct.pack('>I', len(body) + 4) + body)

    def _recv(self):
        while len(self.buf) < 5:
            self._fill()
        kind, n = self.buf[:1], struct.unpack('>I', self.buf[1:5])[0]
        while len(self.buf) < 1 + n:
            self._fill()
        body, self.buf = self.buf[5:1 + n], self.buf[1 + n:]
        if kind == b'E':
            fields = dict((f[:1], f[1:].decode('utf-8', 'replace'))
                          for f in body.split(b'\0') if f)
            raise PgError(fields.get(b'M', 'server error'))
        return kind, body

    def _fill(self):
        got = self.sock.recv(65536)
        if not got:
            raise PgError('connection closed')
        self.buf += got

    def _startup(self):
        params = b''.join(k.encode() + b'\0' + v.encode() + b'\0' for k, v in
                          (('user', self.user), ('database', self.database),
                           ('application_name', 'ddr-boards'))) + b'\0'
        body = struct.pack('>I', 196608) + params
        self.sock.sendall(struct.pack('>I', len(body) + 4) + body)
        scram = None
        while True:
            kind, body = self._recv()
            if kind == b'R':
                code = struct.unpack('>I', body[:4])[0]
                if code == 0:
                    continue                                # AuthenticationOk
                if code == 3:
                    self._send(b'p', self.password.encode() + b'\0')
                elif code == 5:
                    inner = hashlib.md5((self.password + self.user).encode()).hexdigest()
                    outer = hashlib.md5(inner.encode() + body[4:8]).hexdigest()
                    self._send(b'p', b'md5' + outer.encode() + b'\0')
                elif code == 10:
                    if b'SCRAM-SHA-256\0' not in body[4:]:
                        raise PgError('the server offers no SASL method we know')
                    scram = _Scram(self.password)
                    first = scram.first().encode()
                    self._send(b'p', b'SCRAM-SHA-256\0' + struct.pack('>I', len(first))
                               + first)
                elif code == 11:
                    self._send(b'p', scram.final(body[4:].decode()).encode())
                elif code == 12:
                    if not scram.verify(body[4:].decode()):
                        raise PgError('the server failed SCRAM verification')
                else:
                    raise PgError('unsupported authentication method %d' % code)
            elif kind == b'Z':
                return                                      # ReadyForQuery

    def query(self, sql):
        """[{column: text or None}] for one statement."""
        self._send(b'Q', sql.encode('utf-8') + b'\0')
        cols, rows, err = [], [], None
        while True:
            try:
                kind, body = self._recv()
            except PgError as e:
                err = e                     # still read up to ReadyForQuery
                continue
            if kind == b'T':
                n = struct.unpack('>H', body[:2])[0]
                p = 2
                cols = []
                for _ in range(n):
                    end = body.index(b'\0', p)
                    cols.append(body[p:end].decode())
                    p = end + 1 + 18
            elif kind == b'D':
                n = struct.unpack('>H', body[:2])[0]
                p, vals = 2, []
                for _ in range(n):
                    ln = struct.unpack('>i', body[p:p + 4])[0]
                    p += 4
                    if ln < 0:
                        vals.append(None)
                    else:
                        vals.append(body[p:p + ln].decode('utf-8', 'replace'))
                        p += ln
                rows.append(dict(zip(cols, vals)))
            elif kind == b'Z':
                if err:
                    raise err
                return rows


class _Scram:
    """SCRAM-SHA-256 (RFC 5802 / 7677), the client side, without channel
    binding ("n,,"), which is what Postgres expects over a plain socket."""

    def __init__(self, password):
        self.password = password.encode('utf-8')
        self.nonce = base64.b64encode(secrets.token_bytes(18)).decode()
        self.bare = 'n=,r=' + self.nonce

    def first(self):
        return 'n,,' + self.bare

    def final(self, server_first):
        f = dict(kv.split('=', 1) for kv in server_first.split(','))
        if not f['r'].startswith(self.nonce):
            raise PgError('SCRAM nonce mismatch')
        salted = hashlib.pbkdf2_hmac('sha256', self.password, base64.b64decode(f['s']),
                                     int(f['i']))
        client_key = hmac.new(salted, b'Client Key', hashlib.sha256).digest()
        stored = hashlib.sha256(client_key).digest()
        without_proof = 'c=biws,r=' + f['r']
        self.auth = ','.join((self.bare, server_first, without_proof)).encode()
        sig = hmac.new(stored, self.auth, hashlib.sha256).digest()
        proof = bytes(a ^ b for a, b in zip(client_key, sig))
        self.server_key = hmac.new(salted, b'Server Key', hashlib.sha256).digest()
        return without_proof + ',p=' + base64.b64encode(proof).decode()

    def verify(self, server_final):
        f = dict(kv.split('=', 1) for kv in server_final.split(','))
        want = hmac.new(self.server_key, self.auth, hashlib.sha256).digest()
        return hmac.compare_digest(base64.b64decode(f.get('v', '')), want)


def _literal(text):
    """A SQL string literal. Names here are the boards' own, alphanumeric,
    but quote properly anyway rather than trust that."""
    return "'" + str(text).replace("'", "''") + "'"


def _db():
    return Postgres(os.environ['POL_DATABASE_URL'].strip())


def get(name):
    """The registry row for `name` with its token unsealed ('' if it cannot
    be; has_token says whether one is stored), or None."""
    with _db() as db:
        rows = db.query('SELECT name, token_sealed, app_id, public_key, url, updated_at '
                        'FROM discord_bot WHERE name = %s' % _literal(name))
    if not rows:
        return None
    r = rows[0]
    sealed = r.pop('token_sealed') or ''
    r.update(token=unseal(sealed), has_token=bool(sealed))
    return r


def stamp(names):
    """The newest updated_at among `names` (0 when none has a row), or None
    when the table cannot be read."""
    try:
        with _db() as db:
            rows = db.query('SELECT COALESCE(MAX(updated_at), 0) AS t FROM discord_bot '
                            'WHERE name IN (%s)' % ','.join(_literal(n) for n in names))
        return float(rows[0]['t']) if rows else 0.0
    except (OSError, PgError, ValueError, KeyError):
        return None


def watch(names, label='boards', every=None, exit_fn=None, unread=False):
    """Exit the process when one of `names` changes in the registry, so the
    container's restart policy brings it back on the new credentials. A token
    is baked into Gateway sockets and feed threads; restarting is the honest
    reload.

    `unread` says the credentials were never read (the registry was down at
    startup). Then the first time it answers is itself a reason to restart:
    taking that answer as the baseline instead would leave the bots off for
    good after a host reboot that races Postgres."""
    every = float(os.environ.get('POL_BOT_RELOAD_EVERY', '60') or 60) if every is None else every
    if every <= 0 or not names:
        return None
    exit_fn = exit_fn or (lambda: os._exit(0))
    base = {'t': None if unread else stamp(names)}

    def loop():
        while True:
            time.sleep(every)
            t = stamp(names)
            if t is None:
                continue
            if base['t'] is None:
                log('%s: the bot registry is readable again; restarting to load the '
                    'credentials for %s' % (label, ','.join(names)))
                exit_fn()
                return
            if t != base['t']:
                log('%s: the bot registry changed for %s; restarting on the new '
                    'credentials' % (label, ','.join(names)))
                exit_fn()
                return

    t = threading.Thread(target=loop, name='polregistry-watch', daemon=True)
    t.start()
    return t


# ── Valkey: one SET, to tell the admin page what a bot runs on ───────────────

def kv_set(key, value, ttl=None):
    """SET <prefix><key> value [EX ttl] over plain RESP. Best effort: False
    when there is no Valkey or it did not answer +OK."""
    url = os.environ.get('POL_VALKEY_URL', '').strip()
    if not url:
        return False
    u = urllib.parse.urlparse(url)
    key = os.environ.get('POL_KV_PREFIX', 'pol:') + key
    parts = [b'SET', key.encode(), value.encode()]
    if ttl:
        parts += [b'EX', str(int(ttl)).encode()]
    cmd = b'*%d\r\n' % len(parts) + b''.join(b'$%d\r\n%s\r\n' % (len(p), p) for p in parts)
    try:
        with socket.create_connection((u.hostname or '127.0.0.1', u.port or 6379),
                                      timeout=5) as s:
            db = (u.path or '/').lstrip('/')
            if u.password:
                auth = [b'AUTH'] + ([u.username.encode()] if u.username else []) \
                    + [urllib.parse.unquote(u.password).encode()]
                s.sendall(b'*%d\r\n' % len(auth)
                          + b''.join(b'$%d\r\n%s\r\n' % (len(p), p) for p in auth))
                s.recv(256)
            if db and db != '0':
                s.sendall(b'*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n' % (len(db), db.encode()))
                s.recv(256)
            s.sendall(cmd)
            return s.recv(256).startswith(b'+OK')
    except OSError:
        return False


def applied(name, source, app_id, row_at):
    """What the admin page reads to show a bot as live: botcreds:applied:<name>."""
    return kv_set('botcreds:applied:%s' % name, json.dumps(
        {'source': source, 'at': time.time(), 'app_id': app_id, 'row_at': row_at}))
