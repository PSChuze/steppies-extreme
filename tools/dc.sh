#!/bin/sh
# Decompile a range with Ghidra headless. usage: dc.sh <program> <outname> <addr...>
#
# Set GHIDRA to your analyzeHeadless launcher, or export it in the environment.
# The Ghidra project is expected under ghidra/ in the repo root and the
# decompile script under gscripts/.
#
# Two traps, both of which look like a corrupt project and are not:
#  - analyzeHeadless ends in `pause` on Windows, so stdin must be /dev/null or
#    it sits at "Press any key to continue" holding the project lock.
#  - the JVM releases the lock a moment AFTER the script's last output, so a
#    back-to-back run can still lose it. Retry on LockException.
GHIDRA="${GHIDRA:-analyzeHeadless}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJ="$ROOT/ghidra"
PROG="$1"; OUT="$2"; shift 2
ARGS=""
for a in "$@"; do ARGS="$ARGS $a"; done
mkdir -p "$ROOT/out"
n=0
while [ $n -lt 6 ]; do
  "$GHIDRA" "$PROJ" DDR64 -process "$PROG" -noanalysis -scriptPath "$ROOT/gscripts" \
    -postScript DecompAt.java $ARGS > "$ROOT/out/$OUT.log" 2>&1 < /dev/null
  grep -q "Unable to lock project" "$ROOT/out/$OUT.log" || break
  n=$((n + 1))
  sleep 5
done
sed -n '/DecompAt.java>/,$p' "$ROOT/out/$OUT.log" | sed 's/^INFO  DecompAt.java> //'
