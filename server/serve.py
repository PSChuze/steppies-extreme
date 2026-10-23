#!/usr/bin/env python3
"""Run the whole server without Docker: gate, STUN, web and boards together.

    python3 server/serve.py --state ./state

This is what docker-compose.yml does, for the machines where it cannot be
used. Docker Desktop on Windows and macOS rewrites the source address of every
incoming packet, and the server needs the real one: STUN reports it back to
the console, the match relay pairs consoles by it, and the gate picks a LAN or
an internet address for each client from it. So on those systems the setup
program runs this instead, with the Python inside it.

Each service runs as its own process, as each runs in its own container under
compose, so a crash in one leaves the others up. A service that stops is
started again after a short wait, the wait growing while it keeps failing.
Ctrl+C (or a file named serve.stop in the state folder, which is how the setup
program stops a server it started in the background) stops them all.

THE FLAGS BELOW ARE docker-compose.yml's. Keep the two in step: a flag added
to a service there belongs in commands() here, with /state turned into the
state folder. tests/test_setup_serve.py compares them.

Settings come from the .env file beside docker-compose.yml, the same file
compose reads: DDR_SERVER_NAME, DDR_MOTD, DDR_PUBLIC_ADDR, DDR_ADMIN_TOKEN and
the boards' DDR_BOARDS_* values. Every value in it is passed to every service
as an environment variable, as compose's environment: entries do.

Inside the frozen setup program sys.executable is the program, not a Python,
so the services are started as `<program> --run-script <script> <args>`, which
the program hands to runpy. Standard library only.

It also updates the server when the OpenLobby admin panel asks (updates.py):
the gate leaves update.request in the state folder, and this runs the setup
program's update, which only replaces the files, then starts everything again
from the new files, itself included. Progress goes to update.json, which the
gate reports to the panel.
"""
import argparse
import datetime
import os
import re
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import updates  # noqa: E402
SERVICES = ("gate", "stun", "web", "boards")
# The gate's admin port, for the OpenLobby panel. Only loopback here: the panel
# reaches it through a relay container (setup.py starts it, server/adminrelay.py),
# and Docker Desktop's host.docker.internal leads to this machine's loopback.
ADMIN_PORT = 19591
ADMIN_BIND = "127.0.0.1"
PID_FILE = "serve.pid"
STOP_FILE = "serve.stop"
FROZEN = getattr(sys, "frozen", False)
# An update that prints nothing for this long has hung.
UPDATE_TIMEOUT = 30 * 60
RESTARTING = "Restarting with the new version"
# Flags only this runner passes, because compose gives the same thing another
# way (the /state mount), and flags whose value differs on purpose.
NATIVE_ONLY = {"web": {"--state-dir", "--reg-file"}}
NATIVE_VALUE = {"gate": {"--admin-bind"}}


def supports(script, flag):
    """True when the script in server/ knows `flag`. Lets this runner keep
    working beside an older or newer gate.py or web.py while a flag is being
    added there."""
    try:
        with open(os.path.join(HERE, script), encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return False
    return ("'%s'" % flag) in text or ('"%s"' % flag) in text


def commands(state, env):
    """{service: [script, args...]}: docker-compose.yml's commands, with the
    state folder in place of /state and the .env values compose would
    substitute. Keep in step with docker-compose.yml."""
    name = env.get("DDR_SERVER_NAME") or "DDR"
    motd = env.get("DDR_MOTD") or "DDR ONLINE"
    public = env.get("DDR_PUBLIC_ADDR") or ""
    gate = ["gate.py",
            "--host=0.0.0.0",
            "--port=9573",
            "--also-listen=19573,19570,29573,29570",
            "--keyfile=" + os.path.join(state, "xorkey.bin"),
            "--state-file=" + os.path.join(state, "state.json"),
            "--reply-empty",
            "--serve-svrinfo",
            "--serve-svrlist",
            "--svr-name=" + name,
            "--svr-label=" + name[:16],
            "--motd=" + motd,
            "--pair",
            "--serve-block",
            "--serve-rc",
            "--sn-comp=open",
            "--sn-songs=online",
            "--udp-relay"]
    stun = ["stun.py", "--host=0.0.0.0", "--port=3478", "--alt-port=3479"]
    if public:
        gate.append("--public-addr=" + public)
        stun.append("--public-addr=" + public)
    if supports("gate.py", "--admin-port"):
        gate += ["--admin-port=%d" % ADMIN_PORT, "--admin-bind=" + ADMIN_BIND]
    web = ["web.py", "--host=0.0.0.0", "--port=19580"]
    if supports("web.py", "--state-dir"):
        web.append("--state-dir=" + state)
    else:
        web.append("--reg-file=" + os.path.join(state, "registrations.json"))
    boards = ["boards.py",
              "--state-dir=" + state,
              "--e2-port=19581",
              "--sn-port=19582",
              "--sn2-port=19583"]
    return {"gate": gate, "stun": stun, "web": web, "boards": boards}


def launcher():
    """How to start a Python script: this Python, or the frozen setup program's
    --run-script mode."""
    if FROZEN:
        return [sys.executable, "--run-script"]
    return [sys.executable, "-u"]


def read_env(path):
    """KEY=value lines of a .env file, as compose reads them (no quotes, no
    expansion). Missing file: no values."""
    values = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line.rstrip("\r\n"))
                if m:
                    values[m.group(1)] = m.group(2).strip()
    except OSError:
        pass
    return values


# --- the runner's own files ------------------------------------------------------

def pid_alive(pid):
    """True while process `pid` runs."""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        kernel = ctypes.windll.kernel32
        handle = kernel.OpenProcess(0x1000, False, pid)     # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ok = kernel.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel.CloseHandle(handle)
        return bool(ok) and code.value == 259               # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def running_pid(state):
    """The pid of the runner using this state folder, or 0."""
    try:
        with open(os.path.join(state, PID_FILE), encoding="ascii") as f:
            pid = int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0
    return pid if pid != os.getpid() and pid_alive(pid) else 0


def kill_tree(pid):
    """Stop a process and everything it started. On Windows a frozen program is
    two processes (PyInstaller's unpacker and the Python it runs), and
    terminating the first would leave the second behind."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        return
    for target in (lambda: os.killpg(pid, signal.SIGTERM), lambda: os.kill(pid, signal.SIGTERM)):
        try:
            target()
            return
        except OSError:
            continue


# --- running the services --------------------------------------------------------

class Service:
    """One child process, and when to start it again after it stops."""

    def __init__(self, name, argv):
        self.name, self.argv = name, argv
        self.proc = None
        self.started = 0.0
        self.wait = 2.0
        self.next_start = 0.0


class Runner:
    def __init__(self, state, env, only=None, out=None, clock=time.monotonic):
        self.state, self.env = state, env
        self.out = out or sys.stdout
        self.clock = clock
        self.lock = threading.Lock()
        self.stopping = False
        self.relaunch = False
        cmds = commands(state, env)
        self.services = [Service(n, cmds[n]) for n in SERVICES if not only or n in only]

    def log(self, who, text):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            try:
                self.out.write("%s %-6s| %s\n" % (stamp, who, text))
                self.out.flush()
            except (OSError, ValueError):
                pass

    def child_env(self):
        env = dict(os.environ)
        env.update(self.env)
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["DDR_STATE_DIR"] = self.state
        # Tells the gate this runner can update the server (updates.py).
        env["DDR_SUPERVISED"] = "1"
        # A frozen program started by another copy of itself would otherwise
        # share that copy's unpacked files, which vanish when it exits.
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        return env

    def start(self, svc):
        argv = launcher() + [os.path.join(HERE, svc.argv[0])] + svc.argv[1:]
        kw = {}
        if os.name == "nt":
            kw["creationflags"] = 0x08000000                # CREATE_NO_WINDOW: no console per service
        # Elsewhere the services stay in this runner's process group, so
        # stopping the group (setup.py does when the runner does not answer)
        # stops them too.
        svc.proc = subprocess.Popen(argv, cwd=HERE, env=self.child_env(), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)
        svc.started = self.clock()
        self.log("serve", "started %s (pid %d)" % (svc.name, svc.proc.pid))
        threading.Thread(target=self.pump, args=(svc, svc.proc), daemon=True).start()

    def pump(self, svc, proc):
        for raw in proc.stdout:
            self.log(svc.name, raw.decode("utf-8", "replace").rstrip("\r\n"))
        proc.stdout.close()

    def check(self):
        """Start what is not running and is due; note what stopped."""
        now = self.clock()
        for svc in self.services:
            if svc.proc is not None and svc.proc.poll() is not None:
                code = svc.proc.returncode
                ran = now - svc.started
                # One that ran for a while had a one-off failure; one that dies
                # at once will likely die again, so wait longer each time.
                svc.wait = 2.0 if ran > 60 else min(svc.wait * 2, 60.0)
                svc.next_start = now + svc.wait
                self.log("serve", "%s stopped (exit %s); starting it again in %d seconds"
                         % (svc.name, code, svc.wait))
                svc.proc = None
            if svc.proc is None and now >= svc.next_start and not self.stopping:
                try:
                    self.start(svc)
                except OSError as e:
                    svc.next_start = now + 60
                    self.log("serve", "could not start %s (%s); trying again in a minute" % (svc.name, e))

    def setup_command(self):
        """The setup program's update, files only: this runner restarts
        everything itself afterwards."""
        args = ["--folder", ROOT, "--update", "--yes", "--files-only"]
        if FROZEN:
            return [sys.executable] + args
        return [sys.executable, "-u", os.path.join(ROOT, "setup.py")] + args

    def update(self):
        """Run the update the panel asked for. True when the new files are in
        place and everything should start again from them."""
        try:
            os.remove(os.path.join(self.state, updates.REQUEST_FILE))
        except OSError:
            pass
        self.log("serve", "the admin panel asked for an update")
        updates.write_state(self.state, state="updating", message="Looking for the newest release")
        env = dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1", PYTHONIOENCODING="utf-8")
        try:
            proc = subprocess.Popen(self.setup_command(), cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    creationflags=0x08000000 if os.name == "nt" else 0)
        except OSError as e:
            updates.write_state(self.state, state="failed", why="The update could not start (%s)." % e)
            return False
        lines = []
        reader = threading.Thread(target=lambda: lines.extend(proc.stdout), daemon=True)
        reader.start()
        deadline = time.monotonic() + UPDATE_TIMEOUT
        seen, last = 0, ""
        while proc.poll() is None or seen < len(lines) or reader.is_alive():
            for raw in lines[seen:]:
                text = raw.decode("utf-8", "replace").strip()
                if text:
                    last = text
                    self.log("update", text)
                    updates.write_state(self.state, state="updating", message=text[:200])
                deadline = time.monotonic() + UPDATE_TIMEOUT
            seen = len(lines)
            if time.monotonic() > deadline:
                kill_tree(proc.pid)
                updates.write_state(self.state, state="failed",
                                    why="The update stopped answering and was ended.")
                return False
            if proc.poll() is not None and not reader.is_alive() and seen == len(lines):
                break
            time.sleep(0.2)
        if proc.returncode != 0:
            updates.write_state(self.state, state="failed", why=last or "The update failed.")
            self.log("serve", "update failed; still running the old version")
            return False
        if "newest version" in last.lower():
            updates.write_state(self.state)
            return False
        updates.write_state(self.state, state="updating", message=RESTARTING)
        return True

    def stop_requested(self):
        return os.path.exists(os.path.join(self.state, STOP_FILE))

    def stop_all(self):
        self.stopping = True
        for svc in self.services:
            if svc.proc is not None and svc.proc.poll() is None:
                self.log("serve", "stopping %s" % svc.name)
                if os.name == "nt":
                    kill_tree(svc.proc.pid)
                else:
                    svc.proc.terminate()
        deadline = time.monotonic() + 10
        for svc in self.services:
            if svc.proc is None:
                continue
            try:
                svc.proc.wait(max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                svc.proc.kill()
                svc.proc.wait()
        self.log("serve", "all stopped")

    def run(self, tick=1.0):
        pid_path = os.path.join(self.state, PID_FILE)
        stop_path = os.path.join(self.state, STOP_FILE)
        try:
            os.remove(stop_path)
        except OSError:
            pass
        with open(pid_path, "w", encoding="ascii") as f:
            f.write("%d\n" % os.getpid())
        self.log("serve", "state folder %s" % self.state)
        progress = updates.read_state(self.state)
        if progress.get("state") == "updating":
            if progress.get("message") == RESTARTING:
                updates.write_state(self.state)          # this start is that restart
            else:
                updates.write_state(self.state, state="failed",
                                    why="The update was cut short when DDR Online stopped. Try it again.")
        request_path = os.path.join(self.state, updates.REQUEST_FILE)
        try:
            while not self.stopping:
                if self.stop_requested():
                    self.log("serve", "asked to stop")
                    break
                if os.path.exists(request_path) and self.update():
                    self.relaunch = True
                    break
                self.check()
                time.sleep(tick)
        except KeyboardInterrupt:
            self.log("serve", "Ctrl+C")
        finally:
            self.stop_all()
            for path in (pid_path, stop_path):
                try:
                    os.remove(path)
                except OSError:
                    pass


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=os.path.join(os.path.dirname(HERE), "state"),
                    help="the state folder, /state under compose (default: state beside server/)")
    ap.add_argument("--env-file", default=os.path.join(os.path.dirname(HERE), ".env"),
                    help="settings, as compose reads them (default: .env beside server/)")
    ap.add_argument("--only", default="", help="comma-separated services to run (default: all)")
    ap.add_argument("--after", type=int, default=0, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    state = os.path.abspath(args.state)
    os.makedirs(state, exist_ok=True)
    # Started by an older runner after an update: let it finish exiting first.
    for _ in range(120):
        if not args.after or not pid_alive(args.after):
            break
        time.sleep(0.5)
    other = running_pid(state)
    if other:
        sys.exit("already running (process %d) for %s" % (other, state))
    only = {s.strip() for s in args.only.split(",") if s.strip()}
    unknown = only - set(SERVICES)
    if unknown:
        sys.exit("unknown service: %s (there are %s)" % (", ".join(sorted(unknown)), ", ".join(SERVICES)))
    runner = Runner(state, read_env(args.env_file), only)

    def on_signal(signum, frame):
        runner.stopping = True

    for name in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), on_signal)
    runner.run()
    if runner.relaunch:
        relaunch(state, args)


def relaunch(state, args):
    """Start a new runner from the files the update put in place, writing to
    the same log, and leave it the state folder."""
    cmd = launcher() + [os.path.abspath(__file__), "--state", state, "--env-file",
                        os.path.abspath(args.env_file), "--after", str(os.getpid())]
    if args.only:
        cmd += ["--only", args.only]
    env = dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1", PYTHONIOENCODING="utf-8")
    try:
        out = sys.stdout.fileno()
    except (AttributeError, OSError, ValueError):
        out = subprocess.DEVNULL
    kw = {"start_new_session": True}
    if os.name == "nt":
        kw = {"creationflags": 0x08000000 | 0x00000200}  # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(cmd, cwd=HERE, env=env, stdin=subprocess.DEVNULL, stdout=out,
                     stderr=subprocess.STDOUT, close_fds=True, **kw)


if __name__ == "__main__":
    main()
