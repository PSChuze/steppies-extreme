# server

Four processes, no dependencies beyond the standard library.

| file | does |
|---|---|
| `gate.py` | gate, account and lobby for both games |
| `stun.py` | STUN responder for the client's NAT check |
| `web.py` | SuperNOVA's HTTP service, and the operator page at `/admin` |
| `schedule.py` | ranking challenge calendar and generator |
| `content.py` | operator-edited news and challenges |
| `results.py` | result decoders, and the ranking/log/stat queries |
| `db.py` | SQLite storage for accounts, player files, friends and results |
| `admin.py` | the operator page |
| `selftest.py` | offline checks |

See the top-level README for how to run them.

## The key

Every frame is XOR obfuscated with a repeating four-byte key. The gate does not
need to be told it: on the first complete frame it tries all 65536 opcode
candidates and checks each against the frame's MD5, which recovers the key in a
fraction of a second. The client computes a correct digest even though it
ignores incoming ones, which is what makes this work.

The recovered key is written to the keyfile and reused after that.

## selftest.py

```sh
python3 selftest.py
```

Eighteen checks: header round trip, key recovery across four keys including all
zeroes and all `ff`, zero-length payloads, XOR index continuity across the
header boundary, and a socket session end to end. No client needed.

## Useful numbers

The client gives up on a request after about 901 polls, near enough 15 seconds,
and puts up a busy indicator at about 181 polls, near enough 3 seconds. If
something hangs for 15 seconds and then errors, that is the client's timeout and
not a crash.

A zero-length reply is legal and the client jumps straight to "message
complete". `--reply-empty` answers everything that way, which is a cheap way to
see how far a login walks without real payloads. It will stall; the useful part
is where.
