"""Is a newer DDR Online out, and updating it from the admin panel.

The OpenLobby admin panel lists, for every game, whether it runs its newest
version and what changed since (pol-server docs/installs.md, "Updates"). This
works that out for DDR and keeps the files the update is driven by.

Which version runs:

  1. DDR_REVISION, "<commit> [<ISO date>]", when whoever started the server
     knows better (a hand deploy, a build of your own);
  2. server/version.txt, which `git archive` fills in with the commit, so every
     release zip and every setup program carries its own version;
  3. the git checkout the server runs from, read straight from .git.

What is newest depends on how the server is updated. An install from a release
(the setup program) updates to the newest GitHub release; a git checkout
follows the main branch. DDR_UPDATE_TRACK=release|main overrides the guess.

GitHub is asked without a token (60 requests an hour per address), so answers
are kept an hour, ten minutes after a failure, and fetched on a thread of their
own: status.json waits for nothing. Every failure is an "unknown" answer with a
sentence saying why. DDR_UPDATE_REPO names the repository, "off" leaves the
report out.

Updating from the panel ("Update" button) is possible only where the setup
program's supervisor (serve.py) runs the server, the Windows and macOS installs.
The panel's request leaves update.request in the state folder; the supervisor
does the work and keeps its progress in update.json, which the report shows.
A Linux install runs in Docker and is updated by OpenLobby's deployer instead,
with the command the setup program gave the panel when it paired.
"""
import datetime
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_REPO = 'PSChuze/steppies-extreme'
API = 'https://api.github.com'
HOW = 'Run DDR Online Setup and choose Update.'
TTL = 3600.0
TTL_FAILED = 600.0
TIMEOUT = 10.0
MAX_CHANGES = 50
REQUEST_FILE = 'update.request'
STATE_FILE = 'update.json'
_SHA = re.compile(r'^[0-9a-f]{7,40}$')
_REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')


# -- which version runs ------------------------------------------------------

def _git_head(root=ROOT):
    """The commit a git checkout has out, read from .git without git."""
    git = os.path.join(root, '.git')
    try:
        with open(os.path.join(git, 'HEAD'), encoding='ascii') as f:
            head = f.read().strip()
    except OSError:
        return ''
    if not head.startswith('ref: '):
        return head if _SHA.match(head) else ''
    ref = head[5:]
    try:
        with open(os.path.join(git, *ref.split('/')), encoding='ascii') as f:
            sha = f.read().strip()
            return sha if _SHA.match(sha) else ''
    except OSError:
        pass
    try:
        with open(os.path.join(git, 'packed-refs'), encoding='ascii') as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref and _SHA.match(parts[0]):
                    return parts[0]
    except OSError:
        pass
    return ''


def running():
    """(commit, built_at): the commit this server runs, '' when it cannot
    tell, and the commit's date when known."""
    given = os.environ.get('DDR_REVISION', '').split()
    if given and _SHA.match(given[0].lower()):
        return given[0].lower(), given[1] if len(given) > 1 else ''
    try:
        with open(os.path.join(HERE, 'version.txt'), encoding='utf-8') as f:
            stamp = f.read().split()
    except OSError:
        stamp = []
    if stamp and _SHA.match(stamp[0]):
        return stamp[0], stamp[1] if len(stamp) > 1 else ''
    return _git_head(), ''


def track():
    """'main' for a git checkout, 'release' for an installed release."""
    chosen = os.environ.get('DDR_UPDATE_TRACK', '').strip().lower()
    if chosen in ('main', 'release'):
        return chosen
    return 'main' if os.path.isdir(os.path.join(ROOT, '.git')) else 'release'


def iso(stamp):
    """A GitHub or git date as ISO 8601 UTC ("2026-10-22T08:30:00Z"), or ''."""
    if not isinstance(stamp, str) or not stamp:
        return ''
    try:
        t = datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    except ValueError:
        return ''
    if t.tzinfo is None:
        t = t.replace(tzinfo=datetime.timezone.utc)
    return t.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# -- what is newest ----------------------------------------------------------

class Failed(Exception):
    """A check that could not answer; the text is the panel's "why"."""


def github(path):
    """GET an API path -> (status, JSON or None)."""
    req = urllib.request.Request(API + path, headers={
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'ddr-online-update-check'})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, json.loads(r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, None
    except (OSError, ValueError) as e:
        raise Failed('GitHub could not be reached (%s).' % e.__class__.__name__)


def _ok(status, body, what):
    if status in (403, 429):
        raise Failed('GitHub says to wait: too many checks from this address. '
                     'It is tried again later.')
    if status != 200 or not isinstance(body, dict):
        raise Failed('GitHub did not answer about %s (HTTP %s).' % (what, status))
    return body


def check(repo, commit, built_at, which, get=github):
    """The report for the panel, in the shape of pol-server's docs/installs.md
    ("Updates"). Raises Failed with the reason when it cannot tell."""
    if not commit:
        raise Failed('This copy does not say which version it is (no version.txt '
                     'from a release, no git checkout, no DDR_REVISION).')
    if which == 'release':
        status, body = get('/repos/%s/releases/latest' % repo)
        if status == 404:
            raise Failed('No release of DDR Online has been published yet.')
        tag = _ok(status, body, 'the newest release').get('tag_name')
        if not isinstance(tag, str) or not re.match(r'^[A-Za-z0-9._-]+$', tag):
            raise Failed('The newest release has no usable tag.')
        ref = tag
    else:
        ref = 'main'
    head = _ok(*get('/repos/%s/commits/%s' % (repo, ref)), what='the newest version')
    latest = str(head.get('sha') or '')
    if not _SHA.match(latest):
        raise Failed('GitHub did not say which commit is the newest.')
    latest_date = iso(((head.get('commit') or {}).get('committer') or {}).get('date'))
    report = {'running': {'commit': commit, 'built_at': iso(built_at) or None},
              'latest': {'commit': latest, 'date': latest_date or None},
              'behind': 0, 'changes': [], 'update': 'current', 'why': None,
              'how': HOW}
    if latest.startswith(commit) or commit.startswith(latest):
        return report
    status, cmp_ = get('/repos/%s/compare/%s...%s' % (repo, commit, latest))
    if status == 404:
        raise Failed('The running version is not in %s: a build of your own?' % repo)
    cmp_ = _ok(status, cmp_, 'what changed')
    if cmp_.get('behind_by'):
        raise Failed('The running version has changes of its own, so it is not '
                     'simply behind the newest one.')
    changes = []
    for c in reversed(cmp_.get('commits') or []):
        if len(c.get('parents') or []) > 1:
            continue                                  # merges say nothing new
        info = c.get('commit') or {}
        changes.append({'commit': str(c.get('sha') or ''),
                        'date': iso((info.get('committer') or {}).get('date')) or None,
                        'subject': str(info.get('message') or '').split('\n', 1)[0][:200]})
    report.update(behind=int(cmp_.get('ahead_by') or len(changes)),
                  changes=changes[:MAX_CHANGES],
                  update='available' if cmp_.get('ahead_by') else 'current')
    return report


class Checker:
    """The report, kept between checks and refreshed in the background."""

    def __init__(self, repo=None, get=github, clock=time.monotonic):
        self.repo = repo if repo is not None else (
            os.environ.get('DDR_UPDATE_REPO', '').strip() or DEFAULT_REPO)
        self.get, self.clock = get, clock
        self.lock = threading.Lock()
        self.report, self.until, self.busy = None, 0.0, False

    def enabled(self):
        return self.repo.lower() != 'off' and bool(_REPO.match(self.repo))

    def refresh(self):
        commit, built_at = running()
        try:
            report, ttl = check(self.repo, commit, built_at, track(), self.get), TTL
        except Failed as e:
            report, ttl = unknown(str(e), commit, built_at), TTL_FAILED
        except Exception as e:                       # never let a check break status.json
            report, ttl = unknown('The check failed (%s).' % e.__class__.__name__,
                                  commit, built_at), TTL_FAILED
        with self.lock:
            self.report, self.until, self.busy = report, self.clock() + ttl, False

    def get_report(self, wait=0.0):
        """The last report, starting a check when it is due. None until the
        first check has answered."""
        with self.lock:
            due = not self.busy and self.clock() >= self.until
            if due:
                self.busy = True
        if due:
            t = threading.Thread(target=self.refresh, name='update-check', daemon=True)
            t.start()
            if wait:
                t.join(wait)
        with self.lock:
            return dict(self.report) if self.report else None


def unknown(why, commit='', built_at=''):
    return {'running': {'commit': commit or None, 'built_at': iso(built_at) or None},
            'latest': {'commit': None, 'date': None}, 'behind': None,
            'changes': [], 'update': 'unknown', 'why': why, 'how': HOW}


# -- updating from the panel (native installs) -------------------------------

def supervised():
    """True when serve.py runs this server and can update it."""
    return os.environ.get('DDR_SUPERVISED') == '1'


def read_state(state_dir):
    """The supervisor's progress: {"state": "updating", "message"} or
    {"state": "failed", "why"}, or {} when no update is under way."""
    try:
        with open(os.path.join(state_dir, STATE_FILE), encoding='utf-8') as f:
            got = json.load(f)
    except (OSError, ValueError):
        return {}
    return got if isinstance(got, dict) and got.get('state') in ('updating', 'failed') else {}


def write_state(state_dir, **fields):
    """Replace the progress file; no fields removes it."""
    path = os.path.join(state_dir, STATE_FILE)
    if not fields:
        try:
            os.remove(path)
        except OSError:
            pass
        return
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(dict(fields, at=int(time.time())), f)
    os.replace(tmp, path)


def request(state_dir, actor):
    """Ask the supervisor to update. (HTTP status, answer) for the panel."""
    if not supervised():
        return 503, {'ok': False, 'msg': 'This server is not run by DDR Online Setup, '
                                         'so it cannot update itself. ' + HOW}
    if read_state(state_dir).get('state') == 'updating' or \
            os.path.exists(os.path.join(state_dir, REQUEST_FILE)):
        return 409, {'ok': False, 'msg': 'It is already updating.'}
    tmp = os.path.join(state_dir, REQUEST_FILE + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump({'actor': actor, 'at': int(time.time())}, f)
    os.replace(tmp, os.path.join(state_dir, REQUEST_FILE))
    return 202, {'ok': True, 'msg': 'Updating. DDR Online restarts by itself when '
                                    'the new version is in place.'}


def status_block(checker, state_dir):
    """The "update" object for status.json, or None to leave it out."""
    if not checker.enabled():
        return None
    report = checker.get_report() or unknown('The first check is still running.',
                                             *running())
    if supervised() and track() == 'release':
        report['apply'] = True
    progress = read_state(state_dir)
    if progress.get('state') == 'updating':
        report.update(state='updating', message=progress.get('message') or 'Updating')
    elif progress.get('state') == 'failed':
        report.update(state='failed', why=progress.get('why') or 'The update failed.')
    return report
