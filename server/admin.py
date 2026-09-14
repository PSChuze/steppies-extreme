#!/usr/bin/env python3
"""Operator page for news and ranking challenges.

Served by web.py on its own port, off by default. Everything it edits is
optional: with nothing set the gate generates a challenge from the calendar and
uses its built-in news, so this page is for saying something specific, not for
making the server work.

The page is one screen with no JavaScript and no assets, because it is served by
a socket loop rather than a framework, and because an operator page that works
in whatever browser is already open beats one that looks better.

Access is by a token in the URL. It is generated on first run and printed to the
log; there is no login, no session and no cookie. That is a deliberate size
choice for a game server on a home network, not a claim that it is hardened.
Do not expose this port to the internet.
"""
import html
import os
import secrets
import urllib.parse

import content

TOKEN_FILE = '/state/admin_token'


def load_token(path=TOKEN_FILE):
    """The admin token, generated and persisted on first use."""
    try:
        with open(path, encoding='utf-8') as f:
            tok = f.read().strip()
        if tok:
            return tok
    except OSError:
        pass
    tok = secrets.token_urlsafe(18)
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(tok + '\n')
        os.chmod(path, 0o600)
    except OSError:
        pass
    return tok


CSS = """
body{font:15px/1.5 system-ui,sans-serif;max-width:52rem;margin:2rem auto;
padding:0 1rem;background:#111;color:#ddd}
h1{font-size:1.3rem}h2{font-size:1.05rem;margin-top:2rem;border-bottom:1px solid #333;
padding-bottom:.3rem}
input,textarea{width:100%;box-sizing:border-box;background:#1b1b1b;color:#eee;
border:1px solid #444;padding:.45rem;font:inherit;border-radius:3px}
textarea{height:5rem}
button{background:#2a4;color:#000;border:0;padding:.45rem 1rem;font:inherit;
border-radius:3px;cursor:pointer;font-weight:600}
button.d{background:#a33;color:#fff;font-weight:400;padding:.3rem .7rem}
.row{border:1px solid #333;padding:.7rem;margin:.6rem 0;border-radius:4px}
.k{color:#888}
code{color:#8cf}
form.inline{display:inline}
"""


def page(body):
    return ('<!doctype html><meta charset=utf-8><title>DDR server</title>'
            '<style>%s</style>%s' % (CSS, body))


def render(tok, status, week, secs, generated):
    c = content.load()
    news = c.get('news') or []
    rc = c.get('rc') or {}
    e = html.escape
    q = '?t=' + urllib.parse.quote(tok)

    out = ['<h1>DDR server</h1>']
    if status:
        out.append('<p class=k>%s</p>' % e(status))

    out.append('<h2>Now running</h2>')
    out.append('<div class=row>Week <b>%d</b> of 60, <b>%d:%02d</b> left on the '
               'clock.<br><span class=k>The week and its countdown come from the '
               'calendar and advance on their own.</span></div>'
               % (week, secs // 3600, (secs // 60) % 60))
    for i, songs in enumerate(generated):
        over = (rc.get('songs') or {}).get(str(i))
        tag = ' <span class=k>(overridden)</span>' if over else ''
        shown = over if over else songs
        out.append('<div class=row>Challenge %d%s<br><code>%s</code></div>'
                   % (i, tag, e(', '.join(str(x) for x in shown))))

    out.append('<h2>News</h2>')
    if not news:
        out.append('<p class=k>None set, so the built-in text is served.</p>')
    for i, n in enumerate(news):
        out.append('<div class=row><b>%s</b><br>%s<br>'
                   '<form class=inline method=post action="/admin/news/delete%s">'
                   '<input type=hidden name=i value="%d">'
                   '<button class=d>delete</button></form></div>'
                   % (e(n.get('title', '')), e(n.get('body', '')), q, i))
    out.append('<form method=post action="/admin/news%s">'
               '<p>Title<br><input name=title maxlength=64 required></p>'
               '<p>Body<br><textarea name=body maxlength=1024></textarea></p>'
               '<button>Add news item</button></form>' % q)

    out.append('<h2>Ranking challenge</h2>')
    out.append('<p class=k>Leave a field blank to keep the generated value. '
               'Song ids are 0 to 73, comma separated. Avoid id 8: it hangs '
               'the client a few minutes into this tab.</p>')
    out.append('<form method=post action="/admin/rc%s">' % q)
    for i in range(4):
        cur = (rc.get('songs') or {}).get(str(i)) or []
        out.append('<p>Challenge %d<br><input name=songs%d value="%s" '
                   'placeholder="generated: %s"></p>'
                   % (i, i, e(', '.join(str(x) for x in cur)),
                      e(', '.join(str(x) for x in generated[i]))))
    out.append('<p>Difficulty (0-2)<br><input name=difficulty value="%s"></p>'
               % e('' if rc.get('difficulty') is None else str(rc['difficulty'])))
    out.append('<p>Stages (1-10)<br><input name=stages value="%s"></p>'
               % e('' if rc.get('stages') is None else str(rc['stages'])))
    out.append('<button>Save</button></form>')
    out.append('<form method=post action="/admin/rc/clear%s">'
               '<button class=d>Clear all overrides</button></form>' % q)
    return page(''.join(out))


def _ids(raw, lo=0, hi=73):
    out = []
    for part in raw.replace(';', ',').split(','):
        part = part.strip()
        if not part:
            continue
        try:
            v = int(part)
        except ValueError:
            continue
        if lo <= v <= hi:
            out.append(v)
    return out


def handle(method, path, query, form, tok, week, secs, generated):
    """Handle an /admin request.

    Returns (status, content_type, body, location) or None if `path` is not
    ours. `location` is set only for redirects, which every change returns so
    that a refresh does not repeat it.

    `query` is the parsed URL query and `form` the parsed POST body; the token
    may arrive in either.
    """
    if not path.startswith('/admin'):
        return None
    given = (query.get('t', [''])[0] or form.get('t', [''])[0])
    if not secrets.compare_digest(given, tok):
        return ('403 Forbidden', 'text/plain',
                'Add ?t=TOKEN to the URL. '
                'The token is printed in the server log at startup.', None)
    q = '?t=' + urllib.parse.quote(tok)
    base = path.rstrip('/') or '/admin'

    if method != 'POST':
        return ('200 OK', 'text/html',
                render(tok, query.get('m', [''])[0], week, secs, generated),
                None)

    c = content.load()
    news = list(c.get('news') or [])
    rc = dict(c.get('rc') or {})
    msg = ''
    if base == '/admin/news':
        title = (form.get('title', [''])[0] or '').strip()[:64]
        body = (form.get('body', [''])[0] or '').strip()[:1024]
        if title:
            news.append({'title': title, 'body': body})
            msg = 'Added %s.' % title
    elif base == '/admin/news/delete':
        try:
            i = int(form.get('i', ['-1'])[0])
            if 0 <= i < len(news):
                msg = 'Deleted %s.' % news.pop(i).get('title', '')
        except ValueError:
            pass
    elif base == '/admin/rc/clear':
        rc = {}
        msg = 'Overrides cleared; the generated lineup is back.'
    elif base == '/admin/rc':
        songs = {}
        for i in range(4):
            got = _ids(form.get('songs%d' % i, [''])[0])
            if got:
                songs[str(i)] = got
        rc = {}
        if songs:
            rc['songs'] = songs
        d = _ids(form.get('difficulty', [''])[0], 0, 2)
        if d:
            rc['difficulty'] = d[0]
        st = _ids(form.get('stages', [''])[0], 1, 10)
        if st:
            rc['stages'] = st[0]
        msg = 'Saved.' if rc else 'Nothing set; using the generated lineup.'
    else:
        return ('404 Not Found', 'text/plain', 'No such admin page', None)

    content.save({'news': news, 'rc': rc or None})
    where = '/admin' + q + ('&m=' + urllib.parse.quote(msg) if msg else '')
    return ('303 See Other', 'text/html', '<a href="%s">ok</a>' % html.escape(where),
            where)
