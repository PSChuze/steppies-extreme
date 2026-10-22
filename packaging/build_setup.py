"""Build the DDR Online Setup program: python packaging/build_setup.py [--version v1.2.3]

One file made with PyInstaller (pip install pyinstaller==6.11.1), written to
dist/. It carries this repository's committed files as server.zip and unpacks
them into the host's server folder on its first run, so a host needs only the
program (and Docker on Linux). Build each platform's program on that platform.

On Windows and macOS the program is also the Python the server runs on
(setup.py --run-script). PyInstaller only packs the modules setup.py itself
imports, so every standard library module the server's files import is named
here as a hidden import, read from the files at build time.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
NAMES = {"win32": "DDR-Online-Setup", "darwin": "DDR-Online-Setup", "linux": "DDR-Online-Setup-linux-x86_64"}
# Modules a later server version may well start using. Packing them now keeps
# an older setup program able to run a newer server for longer.
EXTRA = ("asyncio", "base64", "binascii", "bisect", "calendar", "collections", "concurrent.futures", "contextlib",
         "copy", "csv", "ctypes", "dataclasses", "datetime", "decimal", "email.utils", "enum", "fnmatch",
         "functools", "glob", "gzip", "hashlib", "heapq", "hmac", "html", "html.parser", "http.client",
         "http.server", "ipaddress", "itertools", "json", "logging", "logging.handlers", "lzma", "math",
         "mimetypes", "operator", "pathlib", "pickle", "platform", "pprint", "queue", "random", "re", "secrets",
         "select", "selectors", "shlex", "signal", "socket", "socketserver", "sqlite3", "ssl", "statistics",
         "string", "struct", "tempfile", "textwrap", "threading", "traceback", "types", "typing",
         "unicodedata", "urllib.error", "urllib.parse", "urllib.request", "uuid", "wsgiref.simple_server",
         "xml.etree.ElementTree", "zipfile", "zlib")


def hidden_imports():
    import setup
    stdlib = getattr(sys, "stdlib_module_names", None)
    names = set(EXTRA)
    for name in setup.server_imports(HERE):
        if stdlib is None or name.split(".")[0] in stdlib:
            names.add(name)
    return sorted(names)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="dev", help="the release tag the program reports and updates from")
    args = ap.parse_args()
    work = os.path.join(HERE, "build", "setup")
    os.makedirs(work, exist_ok=True)
    archive = os.path.join(work, "server.zip")
    subprocess.run(["git", "-C", HERE, "archive", "--format=zip", "--prefix=steppies-extreme/", "-o", archive,
                    "HEAD"], check=True)
    version = os.path.join(work, "server-version.txt")
    with open(version, "w", encoding="utf-8") as f:
        f.write(args.version + "\n")
    name = NAMES.get(sys.platform, NAMES["linux"])
    hidden = []
    for module in hidden_imports():
        hidden += ["--hidden-import", module]
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console",
                    "--name", name, "--distpath", os.path.join(HERE, "dist"), "--workpath", os.path.join(work, "work"),
                    "--specpath", work, "--add-data", archive + os.pathsep + ".",
                    "--add-data", version + os.pathsep + ".", "--paths", HERE] + hidden +
                   [os.path.join(HERE, "setup.py")], check=True, cwd=HERE)
    print(os.path.join(HERE, "dist", name + (".exe" if sys.platform == "win32" else "")))


if __name__ == "__main__":
    main()
