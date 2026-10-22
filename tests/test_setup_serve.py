"""server/serve.py, the runner Windows and macOS use instead of compose: its
commands must stay docker-compose.yml's, it starts a service again after it
stops, and it stops everything when asked."""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
import serve  # noqa: E402


def compose_commands(path=os.path.join(ROOT, "docker-compose.yml")):
    """{service: [command items]} of docker-compose.yml, read without a YAML
    library: each command is a plain list of "- item" lines."""
    out, service, in_command = {}, None, False
    in_services = False
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if indent == 0:
                in_services = line.startswith("services:")
                service, in_command = None, False
                continue
            if not in_services:
                continue
            if indent == 2 and line.strip().endswith(":"):
                service, in_command = line.strip()[:-1], False
            elif indent == 4:
                in_command = line.strip() == "command:"
                if in_command:
                    out[service] = []
            elif in_command and line.strip().startswith("- "):
                item = line.strip()[2:].strip()
                if len(item) > 1 and item[0] == item[-1] and item[0] in "\"'":
                    item = item[1:-1]
                out[service].append(item)
    return out


def substitute(text):
    """${NAME:-default} as compose resolves it with nothing set."""
    return re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-([^}]*))?\}", lambda m: m.group(1) or "", text)


def flags(items):
    out = {}
    for item in items:
        name, _, value = item.partition("=")
        out[name] = value.replace("\\", "/") if _ else None
    return out


class SameAsCompose(unittest.TestCase):
    def test_flags_match_docker_compose(self):
        composed = compose_commands()
        native = serve.commands("/state", {})
        for name in serve.SERVICES:
            items = [substitute(i) for i in composed[name]]
            self.assertEqual(items[:2], ["python3", "-u"], name)
            self.assertEqual(items[2], native[name][0], name)
            want, have = flags(items[3:]), flags(native[name][1:])
            # "auto" is --public-addr's default: compose may spell it out
            # (${DDR_PUBLIC_ADDR:-auto}) where serve.py leaves the flag off.
            for side in (want, have):
                if side.get("--public-addr") == "auto":
                    del side["--public-addr"]
            for skip in serve.NATIVE_ONLY.get(name, ()):
                want.pop(skip, None)
                have.pop(skip, None)
            for differs in serve.NATIVE_VALUE.get(name, ()):
                self.assertEqual(differs in want, differs in have, "%s %s" % (name, differs))
                want.pop(differs, None)
                have.pop(differs, None)
            self.assertEqual(have, want, "serve.py's %s and docker-compose.yml's differ" % name)

    def test_state_folder_replaces_slash_state(self):
        state = os.path.join(tempfile.gettempdir(), "ddr state")
        native = serve.commands(state, {})
        text = " ".join(" ".join(v) for v in native.values())
        self.assertNotIn("/state/", text.replace("\\", "/").replace(state.replace("\\", "/"), "<state>"))
        self.assertIn("--state-dir=" + state, native["boards"])
        self.assertIn("--keyfile=" + os.path.join(state, "xorkey.bin"), native["gate"])

    def test_settings_from_env(self):
        native = serve.commands("/s", {"DDR_SERVER_NAME": "Dance Hall", "DDR_MOTD": "Hi all",
                                       "DDR_PUBLIC_ADDR": "203.0.113.10"})
        self.assertIn("--svr-name=Dance Hall", native["gate"])
        self.assertIn("--svr-label=Dance Hall", native["gate"])
        self.assertIn("--motd=Hi all", native["gate"])
        self.assertIn("--public-addr=203.0.113.10", native["gate"])
        self.assertIn("--public-addr=203.0.113.10", native["stun"])

    def test_admin_port_is_loopback_only(self):
        if not serve.supports("gate.py", "--admin-port"):
            self.skipTest("this gate.py has no admin port")
        gate = serve.commands("/s", {})["gate"]
        self.assertIn("--admin-port=19591", gate)
        self.assertIn("--admin-bind=127.0.0.1", gate)

    def test_frozen_launcher(self):
        with mock.patch.object(serve, "FROZEN", True), mock.patch.object(serve.sys, "executable", "/x/setup"):
            self.assertEqual(serve.launcher(), ["/x/setup", "--run-script"])
        with mock.patch.object(serve, "FROZEN", False):
            self.assertEqual(serve.launcher(), [sys.executable, "-u"])


class EnvFile(unittest.TestCase):
    def test_read_env(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, ".env")
        with open(path, "w", encoding="utf-8") as f:
            f.write("# comment\nDDR_SERVER_NAME=My Server\n#DDR_MOTD=off\nDDR_ADMIN_TOKEN= abc \n")
        self.assertEqual(serve.read_env(path), {"DDR_SERVER_NAME": "My Server", "DDR_ADMIN_TOKEN": "abc"})
        self.assertEqual(serve.read_env(os.path.join(d, "missing")), {})


class Running(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.state = os.path.join(self.dir, "state")
        os.makedirs(self.state)

    def script(self, name, body):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        return path

    def runner(self, script, clock=time.monotonic):
        out = io.StringIO()
        with mock.patch.object(serve, "commands", return_value={"gate": [script]}):
            r = serve.Runner(self.state, {}, only={"gate"}, out=out, clock=clock)
        return r, out

    def test_a_stopped_service_starts_again_later(self):
        now = [100.0]
        r, out = self.runner(self.script("dies.py", "print('bye')\nraise SystemExit(3)\n"), clock=lambda: now[0])
        r.check()
        svc = r.services[0]
        first = svc.proc
        first.wait(30)
        now[0] += 1
        r.check()
        self.assertIsNone(svc.proc)
        self.assertEqual(svc.wait, 4.0)          # it died at once: wait longer than the 2 s base
        now[0] += 1
        r.check()
        self.assertIsNone(svc.proc)              # not yet
        now[0] += 4
        r.check()
        self.assertIsNotNone(svc.proc)
        svc.proc.wait(30)
        time.sleep(0.3)                          # let the output thread catch up
        text = out.getvalue()
        self.assertIn("gate stopped (exit 3); starting it again in 4 seconds", text)
        self.assertIn("| bye", text)

    def test_stop_file_stops_everything(self):
        sleeper = self.script("sleeps.py", "import time\nprint('up', flush=True)\ntime.sleep(120)\n")
        r, out = self.runner(sleeper)
        t = threading.Thread(target=r.run, kwargs={"tick": 0.1}, daemon=True)
        t.start()
        deadline = time.time() + 30
        while time.time() < deadline and "| up" not in out.getvalue():
            time.sleep(0.1)
        with open(os.path.join(self.state, "serve.pid")) as f:
            self.assertEqual(int(f.read()), os.getpid())
        proc = r.services[0].proc
        with open(os.path.join(self.state, serve.STOP_FILE), "w") as f:
            f.write("stop\n")
        t.join(30)
        self.assertFalse(t.is_alive())
        self.assertIsNotNone(proc.poll())
        self.assertFalse(os.path.exists(os.path.join(self.state, "serve.pid")))
        self.assertFalse(os.path.exists(os.path.join(self.state, serve.STOP_FILE)))
        self.assertIn("all stopped", out.getvalue())

    def test_running_pid(self):
        with open(os.path.join(self.state, serve.PID_FILE), "w") as f:
            f.write("%d\n" % os.getpid())
        self.assertEqual(serve.running_pid(self.state), 0)       # that is us
        done = subprocess.Popen([sys.executable, "-c", "pass"])
        done.wait()
        with open(os.path.join(self.state, serve.PID_FILE), "w") as f:
            f.write("%d\n" % done.pid)
        self.assertEqual(serve.running_pid(self.state), 0)
        live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(live.wait)
        self.addCleanup(live.kill)
        with open(os.path.join(self.state, serve.PID_FILE), "w") as f:
            f.write("%d\n" % live.pid)
        self.assertEqual(serve.running_pid(self.state), live.pid)


if __name__ == "__main__":
    unittest.main()
