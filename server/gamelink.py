"""A small signed API on loopback, for a website to talk to the game server.

Used by ddrlink.py. Two locks keep it to the website it is meant for: the
caller must be on loopback (the website runs on the same host), and every
request is signed:

    X-Timestamp: unix seconds, within GAMELINK_SKEW of now (60 by default)
    X-Signature: HMAC-SHA256(GAMELINK_SECRET, timestamp + "\\n" + body), hex

With no secret, or one shorter than 32 characters, the API does not start.
Requests and replies are JSON, and passwords are never logged.
"""
import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get('GAMELINK_SECRET', '').encode()
SKEW = int(os.environ.get('GAMELINK_SKEW', '60'))
ALLOW = {'127.0.0.1', '::1'}
MAX_BODY = 4096


def signature(secret, ts, body):
    return hmac.new(secret, ts.encode() + b'\n' + body, hashlib.sha256).hexdigest()


def serve(routes, port, log=print):
    """Start the API on 127.0.0.1:port in a daemon thread. `routes` maps a
    path to fn(request dict) -> reply dict. Returns the server, or None when
    GAMELINK_SECRET is unset."""
    if len(SECRET) < 32:
        log('account link: GAMELINK_SECRET unset or shorter than 32 characters, off')
        return None

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, code, obj=None):
            out = json.dumps(obj or {}).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def do_POST(self):
            if self.client_address[0] not in ALLOW:
                return self.send(403)
            fn = routes.get(self.path)
            if fn is None:
                return self.send(404)
            try:
                n = int(self.headers.get('Content-Length') or 0)
            except ValueError:
                n = -1
            if not 0 < n <= MAX_BODY:
                return self.send(400)
            body = self.rfile.read(n)
            ts = self.headers.get('X-Timestamp') or ''
            try:
                fresh = abs(time.time() - int(ts)) <= SKEW
            except ValueError:
                fresh = False
            if not fresh or not hmac.compare_digest(
                    signature(SECRET, ts, body),
                    self.headers.get('X-Signature') or ''):
                log('account link: refused %s: bad signature or old timestamp'
                    % self.path)
                return self.send(401)
            try:
                req = json.loads(body)
            except ValueError:
                return self.send(400)
            if not isinstance(req, dict):
                return self.send(400)
            res = fn(req)
            log('account link: %s %s -> %s' % (
                self.path, req.get('account', ''),
                'ok' if res.get('ok') else res.get('error')))
            return self.send(200, res)

    srv = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log('account link: API on 127.0.0.1:%d' % port)
    return srv
