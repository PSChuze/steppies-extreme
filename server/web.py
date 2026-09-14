#!/usr/bin/env python3
"""DDR SuperNOVA web stub -- the piece Extreme 2 does not have.

SuperNOVA's `net_https_mas4` (DATA08) fetches three documents after the gate and
STUN phases succeed. With those hosts still pointed at the dead Konami servers
the HTTP layer returns -1005..-1008 and the client shows UI message 0x6f,
"Failed to connect to the server. Server may currently be under maintenance."
(raised at 0x00a9c6a0 in DATA08). Serving them is the whole job.

The stock URLs live in the service table at 0x002d0128..0x002d0138 and point at
port 80/443, which are taken on the gate host, so `tools/isopatch.py` rewrites
them in the ELF to this port. Paths are shortened to fit the original string
slots -- they are ours to choose:

    /ddrsn/oua/oua.txt          online user agreement
    /ddrsn/oua/pia.txt          privacy / personal information agreement
    /VW/info/                   service information
    /ddrsn/reg/reg.html         account registration      (on demand)
    /ddrsn/reg/chg.html         password change           (on demand)

Every request is logged in full, including ones we do not recognise, because
what else the client asks for is still unknown -- and an unknown path answered
with 404 is far easier to spot in a log than a silent timeout.

Pure stdlib, like gate.py. No framework, nothing to build.
"""
import argparse, os, socket, sys, threading, datetime, urllib.parse

import admin
import schedule

OUA = """DANCE DANCE REVOLUTION SUPERNOVA
ONLINE USER AGREEMENT

This is a private, non-commercial server operated for game preservation.
It is not affiliated with, endorsed by, or connected to Konami or Sony.

The official service was discontinued. This server exists so that the
online mode of a game you already own remains playable.

No warranty is offered. Play data is stored on this server only.

By connecting you agree to use this service for personal play only.
"""

PIA = """DANCE DANCE REVOLUTION SUPERNOVA
PERSONAL INFORMATION AGREEMENT

This private server collects only what the game itself sends: a dancer
name, play records and scores.

Nothing is shared with any third party. Nothing is used for advertising.
No real-world identifying information is requested or wanted.

Play records may be removed at any time on request.
"""

INFO = """DANCE DANCE REVOLUTION SUPERNOVA
SERVICE INFORMATION

Status: online.

This is a private preservation server. Ranking Challenge and Internet
Ranking data are local to this server.
"""

REG = """<html><head><title>Registration</title></head><body>
<h1>Account Registration</h1>
<p>Accounts are created automatically on first login.
No registration is required on this server.</p>
</body></html>
"""

CHG = """<html><head><title>Change Password</title></head><body>
<h1>Change Password</h1>
<p>This server does not use passwords.</p>
</body></html>
"""

ROUTES = {
    '/ddrsn/oua/oua.txt': ('text/plain', OUA),
    '/ddrsn/oua/pia.txt': ('text/plain', PIA),
    '/VW/info/':          ('text/plain', INFO),
    '/VW/info':           ('text/plain', INFO),
    '/ddrsn/reg/reg.html': ('text/html', REG),
    '/ddrsn/reg/chg.html': ('text/html', CHG),
}


REG_POSTS = ('/ddrsn/reg/reg.html', '/ddrsn/reg/chg.html')

# The six fields SuperNOVA posts, in wire order. Built in DATA08 from the format
# strings at 0x00b4cf16: "name=%s" "&passwd=%s" "&email=%s" "&region=%d"
# "&gender=%d" "&age=%d", plus "&pswdnew=%s" for the change-password form.
REG_FIELDS = ('name', 'passwd', 'email', 'region', 'gender', 'age', 'pswdnew')


# Field names whose VALUES are never stored unless --reg-keep-secrets is given.
# 'passwd' and 'pswdnew' are the registration and password-change forms;
# email is personal data with no use here either.
REG_SECRET_FIELDS = {'passwd', 'pswdnew', 'password', 'email'}


def admin_clock():
    return schedule.rc_week()


def admin_generated(week):
    """What the gate will serve this week, so the page shows the real lineup."""
    return [schedule.rc_auto_songs(week, c) for c in range(4)]


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')


def reg_log(addr, path, body, args):
    """Persist a registration, with secrets redacted.

    The gate's account phase is a separate protocol and nothing links these to
    an account, so the password is never read back by anything -- storing it
    would be pure liability for whoever runs the server. What is worth keeping
    is that a registration happened and what SHAPE it had, which is what made
    the field list recoverable without a wire capture.

    So the field NAMES are kept and the secret VALUES are replaced. Pass
    --reg-keep-secrets to store them verbatim; that exists for protocol work on
    your own client, not for a server strangers can reach.
    """
    if not args.reg_file:
        return
    import json
    try:
        fields = dict(urllib.parse.parse_qsl(body.decode('latin1'),
                                             keep_blank_values=True))
    except Exception:
        fields = {'_raw': body.hex()}
    if not getattr(args, 'reg_keep_secrets', False):
        for k in list(fields):
            if k.lower() in REG_SECRET_FIELDS:
                fields[k] = '<redacted>'
    rec = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'from': '%s:%d' % addr, 'path': path, 'fields': fields}
    try:
        try:
            with open(args.reg_file, encoding='utf-8') as f:
                recs = json.load(f)
        except Exception:
            recs = []
        recs.append(rec)
        tmp = args.reg_file + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(recs, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, args.reg_file)
        print('%s   registration #%d saved to %s'
              % (stamp(), len(recs), args.reg_file), flush=True)
    except Exception as e:
        print('%s   could not save registration: %s' % (stamp(), e), flush=True)


def serve(conn, addr, args):
    tag = '[%s:%d]' % addr
    try:
        conn.settimeout(20)
        buf = b''
        while b'\r\n\r\n' not in buf and b'\n\n' not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        if not buf:
            print('%s %s empty request' % (stamp(), tag), flush=True)
            return

        # Split head/body, then read the REST of the body. SuperNOVA posts
        # account registration as application/x-www-form-urlencoded to
        # /ddrsn/reg/reg.html with its OWN User-Agent (DDRSN/1.00 (KONAMI))
        # rather than through the gate protocol -- so the body IS the account
        # data, and dropping it loses the only copy we will ever see.
        if b'\r\n\r\n' in buf:
            head, body = buf.split(b'\r\n\r\n', 1)
        elif b'\n\n' in buf:
            head, body = buf.split(b'\n\n', 1)
        else:
            head, body = buf, b''
        lines = head.replace(b'\r\n', b'\n').split(b'\n')
        clen = 0
        for h in lines[1:]:
            if h.lower().startswith(b'content-length:'):
                try:
                    clen = int(h.split(b':', 1)[1].strip())
                except ValueError:
                    pass
        while len(body) < clen:
            chunk = conn.recv(min(4096, clen - len(body)))
            if not chunk:
                break
            body += chunk
        req = lines[0].decode('latin1', 'replace')
        print('%s %s %s' % (stamp(), tag, req), flush=True)
        for h in lines[1:]:
            if h.strip():
                print('%s %s   | %s' % (stamp(), tag, h.decode('latin1', 'replace')),
                      flush=True)

        if body:
            print('%s %s   body %d bytes:' % (stamp(), tag, len(body)), flush=True)
            for i in range(0, len(body), 16):
                row = body[i:i + 16]
                print('%s %s     %04x  %-47s  %s'
                      % (stamp(), tag, i, row.hex(' '),
                         ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)),
                      flush=True)
            # Decode the form too, so the field NAMES read at a glance.
            try:
                for k, v in urllib.parse.parse_qsl(body.decode('latin1'),
                                                   keep_blank_values=True):
                    print('%s %s     %-18s = %r' % (stamp(), tag, k, v), flush=True)
            except Exception as e:
                print('%s %s     (not form-encoded: %s)' % (stamp(), tag, e),
                      flush=True)

        parts = req.split()
        method = parts[0] if parts else ''
        path = parts[1] if len(parts) > 1 else '/'
        if '://' in path:                      # some clients send absolute URIs
            path = '/' + path.split('://', 1)[1].split('/', 1)[-1]
        path, _, qs = path.partition('?')
        query = urllib.parse.parse_qs(qs, keep_blank_values=True)

        # The operator page. Token-gated and on the same port, because the game
        # only ever asks for the handful of paths above and one listener is one
        # less thing to expose or explain.
        if args.admin and path.startswith('/admin'):
            form = {}
            if body:
                form = urllib.parse.parse_qs(body.decode('latin1', 'replace'),
                                             keep_blank_values=True)
            week, secs = admin_clock()
            got = admin.handle(method, path, query, form, args.admin_token,
                               week, secs, admin_generated(week))
            if got:
                status, ctype, text, location = got
                raw = text.encode('utf-8', 'replace')
                sep = chr(13) + chr(10)
                head = ['HTTP/1.1 ' + status,
                        'Content-Type: ' + ctype + '; charset=utf-8',
                        'Content-Length: ' + str(len(raw))]
                if location:
                    head.append('Location: ' + location)
                head.append('Connection: close')
                conn.sendall((sep.join(head) + sep + sep).encode() + raw)
                print('%s %s   -> %s %s' % (stamp(), tag, status, path),
                      flush=True)
                return

        # Registration / password change are NOT web pages. The client POSTs a
        # urlencoded form and then, at 0x00b204e8 in DATA08:
        #
        #     ld   $v0, 0x20($s4)   ; response body length
        #     slti $v0, $v0, 0xa    ; MUST be < 10 bytes
        #     bnel ...              ; then strtol(body, NULL, 10)
        #     addiu $v0, -0x271f    ; else -10015 -> "Data transfer error."
        #
        # and the strtol result becomes the call's return value, which the caller
        # stores at +0x54 and tests with beqz -- so the body must be a bare
        # decimal integer under 10 bytes, and 0 means success. Serving the HTML
        # page here returns -10015 every time, however valid the form was.
        if method == 'POST' and path in REG_POSTS:
            reg_log(addr, path, body, args)
            raw = ('%d' % args.reg_result).encode()
            conn.sendall(('HTTP/1.0 200 OK\r\n'
                          'Content-Type: text/plain\r\n'
                          'Content-Length: %d\r\n'
                          'Connection: close\r\n\r\n' % len(raw)).encode() + raw)
            print('%s %s   -> 200 %s  result=%d (%d bytes, must be < 10)'
                  % (stamp(), tag, path, args.reg_result, len(raw)), flush=True)
            return

        route = ROUTES.get(path) or ROUTES.get(path.rstrip('/'))
        if route:
            ctype, body = route
            status = '200 OK'
            print('%s %s   -> 200 %s (%d bytes)' % (stamp(), tag, path, len(body)),
                  flush=True)
        else:
            ctype, body = 'text/plain', 'Not Found\n'
            status = '404 Not Found'
            print('%s %s   -> 404 %s  *** UNKNOWN PATH -- add a route ***'
                  % (stamp(), tag, path), flush=True)

        raw = body.encode('latin1', 'replace')
        resp = ('HTTP/1.1 %s\r\n'
                'Server: ddr-web\r\n'
                'Content-Type: %s\r\n'
                'Content-Length: %d\r\n'
                'Connection: close\r\n'
                '\r\n' % (status, ctype, len(raw))).encode('latin1')
        if method != 'HEAD':
            resp += raw
        conn.sendall(resp)
    except Exception as e:
        print('%s %s error: %s' % (stamp(), tag, e), flush=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description='DDR SuperNOVA web stub')
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=19580,
                    help='must match web_port in patches/patches.json, which is '
                         'what the ELF service-table URLs were rewritten to')
    ap.add_argument('--reg-result', type=int, default=0,
                    help='decimal body returned for a registration POST. The '
                         'client strtol()s it and the caller tests it with beqz, '
                         'so 0 = success. MUST render to fewer than 10 bytes.')
    ap.add_argument('--reg-file', default='/state/registrations.json',
                    help='where to append posted registrations (empty to disable). '
                         'Passwords and email are redacted unless '
                         '--reg-keep-secrets is also given.')
    ap.add_argument('--admin', action='store_true', default=True,
                    help='serve the operator page at /admin on this port '
                         '(default on; --no-admin turns it off)')
    ap.add_argument('--no-admin', dest='admin', action='store_false',
                    help=argparse.SUPPRESS)
    ap.add_argument('--admin-token', default='',
                    help='token the operator page requires in ?t=. Generated '
                         'and stored in the state directory if not given.')
    ap.add_argument('--reg-keep-secrets', action='store_true',
                    help='store registration passwords and email addresses in '
                         'plaintext instead of redacting them. For protocol work '
                         'against your OWN client only -- on a server other '
                         'people can reach this collects their passwords, and '
                         'nothing ever reads the file back.')
    args = ap.parse_args()
    if args.admin:
        args.admin_token = args.admin_token or admin.load_token()
    if len('%d' % args.reg_result) >= 10:
        sys.exit('--reg-result %d is %d bytes; the client rejects any '
                 'registration response of 10 bytes or more (-10015)'
                 % (args.reg_result, len('%d' % args.reg_result)))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.listen(16)
    print('ddr-web listening on %s:%d' % (args.host, args.port), flush=True)
    if args.admin:
        wk, secs = admin_clock()
        print('operator page:  http://<this-host>:%d/admin?t=%s'
              % (args.port, args.admin_token), flush=True)
        print('  week %d of 60, %d:%02d left. Nothing needs setting; the '
              'challenge rotates on its own.'
              % (wk, secs // 3600, (secs // 60) % 60), flush=True)
    for p in sorted(ROUTES):
        print('   %s' % p, flush=True)
    print('point dx2web.konamionline.com and info.service.konamionline.com here',
          flush=True)

    while True:
        conn, addr = s.accept()
        threading.Thread(target=serve, args=(conn, addr, args), daemon=True).start()


if __name__ == '__main__':
    main()
