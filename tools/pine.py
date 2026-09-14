#!/usr/bin/env python3
"""
Minimal PINE client for PCSX2 -- read/write live EE memory.

PINE is PCSX2's IPC socket (TCP 127.0.0.1:<slot> on Windows; the slot is
`PINESlot` in PCSX2.ini). This exists because static RE keeps being
one inference away from wrong: with PINE we can just LOOK at what is in memory
instead of arguing about which function the disassembler thinks is the gate.

    python tools/pine.py status              # is anything listening / what game
    python tools/pine.py id                  # game serial, e.g. SLUS-21174
    python tools/pine.py title
    python tools/pine.py read32 0x001d5280
    python tools/pine.py dump   0x001d5280 32
    python tools/pine.py write32 0x001d5280 0x03e00008

If you run more than one PCSX2 instance, give each its own PINE slot in its
PCSX2.ini (EnablePINE, PINESlot); two instances sharing one slot means the
loser gets no PINE and no emulog, which looks like a debugging dead end and is
not one. Pass --slot to pick which instance, and confirm with `id` before
trusting a read. On Windows, which process owns a slot:
    Get-NetTCPConnection -State Listen -LocalPort <slot> | select OwningProcess

Wire format: every request is [u32 total_len][u8 opcode][args...], where
total_len counts its own 4 bytes. Every reply is [u32 total_len][u8 result]
[data...], result 0 = OK.
"""
import argparse
import socket
import struct
import sys

DEFAULT_SLOT = 28012   # override with --slot if your PCSX2 uses a different PINESlot

MSG_READ8, MSG_READ16, MSG_READ32, MSG_READ64 = 0x00, 0x01, 0x02, 0x03
MSG_WRITE8, MSG_WRITE16, MSG_WRITE32, MSG_WRITE64 = 0x04, 0x05, 0x06, 0x07
MSG_VERSION, MSG_TITLE, MSG_ID, MSG_UUID = 0x08, 0x0B, 0x0C, 0x0D
MSG_GAMEVERSION, MSG_STATUS = 0x0E, 0x0F

STATUS = {0: "RUNNING", 1: "PAUSED", 2: "SHUTDOWN"}


class PineError(RuntimeError):
    pass


class Pine:
    def __init__(self, slot=DEFAULT_SLOT, host="127.0.0.1", timeout=5.0):
        self.addr = (host, slot)
        self.timeout = timeout

    def _txn(self, payload):
        """One request/response. PINE closes state per connection, so connect
        fresh each time -- it is local and this is not a hot path."""
        pkt = struct.pack("<I", 4 + len(payload)) + payload
        try:
            s = socket.create_connection(self.addr, timeout=self.timeout)
        except OSError as e:
            raise PineError("cannot reach PINE at %s:%d (%s). Is PCSX2 running "
                            "with EnablePINE=true, and does THIS instance own "
                            "the slot?" % (self.addr[0], self.addr[1], e))
        try:
            s.sendall(pkt)
            head = self._recvn(s, 4)
            total = struct.unpack("<I", head)[0]
            if total < 5:
                raise PineError("short reply header (%d)" % total)
            body = self._recvn(s, total - 4)
        finally:
            s.close()
        if body[0] != 0:
            raise PineError("PINE returned failure code 0x%02x" % body[0])
        return body[1:]

    @staticmethod
    def _recvn(s, n):
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise PineError("connection closed mid-reply")
            buf += c
        return buf

    def read(self, addr, size):
        op = {1: MSG_READ8, 2: MSG_READ16, 4: MSG_READ32, 8: MSG_READ64}[size]
        d = self._txn(struct.pack("<BI", op, addr))
        return int.from_bytes(d[:size], "little")

    def write(self, addr, size, value):
        op = {1: MSG_WRITE8, 2: MSG_WRITE16, 4: MSG_WRITE32, 8: MSG_WRITE64}[size]
        val = int(value).to_bytes(size, "little")
        self._txn(struct.pack("<BI", op, addr) + val)

    def _string(self, op):
        d = self._txn(struct.pack("<B", op))
        n = struct.unpack("<I", d[:4])[0]
        return d[4:4 + n].rstrip(b"\x00").decode("utf-8", "replace")

    def title(self):
        return self._string(MSG_TITLE)

    def game_id(self):
        return self._string(MSG_ID)

    def game_version(self):
        return self._string(MSG_GAMEVERSION)

    def uuid(self):
        return self._string(MSG_UUID)

    def status(self):
        d = self._txn(struct.pack("<B", MSG_STATUS))
        v = struct.unpack("<I", d[:4])[0]
        return STATUS.get(v, "UNKNOWN(%d)" % v)

    def dump(self, addr, nbytes):
        out = b""
        for off in range(0, nbytes, 4):
            out += self.read(addr + off, 4).to_bytes(4, "little")
        return out[:nbytes]


def main():
    ap = argparse.ArgumentParser(description="PCSX2 PINE memory client")
    ap.add_argument("--slot", type=int, default=DEFAULT_SLOT)
    ap.add_argument("cmd", choices=["status", "id", "title", "version", "uuid",
                                    "read8", "read16", "read32", "read64",
                                    "write8", "write16", "write32", "dump"])
    ap.add_argument("args", nargs="*")
    a = ap.parse_args()
    p = Pine(slot=a.slot)
    try:
        if a.cmd == "status":
            print("status : %s" % p.status())
            print("id     : %s" % p.game_id())
            print("title  : %s" % p.title())
        elif a.cmd == "id":
            print(p.game_id())
        elif a.cmd == "title":
            print(p.title())
        elif a.cmd == "version":
            print(p.game_version())
        elif a.cmd == "uuid":
            print(p.uuid())
        elif a.cmd.startswith("read"):
            size = int(a.cmd[4:]) // 8
            addr = int(a.args[0], 0)
            print("0x%08x = 0x%0*x" % (addr, size * 2, p.read(addr, size)))
        elif a.cmd.startswith("write"):
            size = int(a.cmd[5:]) // 8
            addr, val = int(a.args[0], 0), int(a.args[1], 0)
            before = p.read(addr, size)
            p.write(addr, size, val)
            after = p.read(addr, size)
            print("0x%08x : 0x%0*x -> 0x%0*x%s"
                  % (addr, size * 2, before, size * 2, after,
                     "" if after == val else "   !! WRITE DID NOT STICK"))
        elif a.cmd == "dump":
            addr = int(a.args[0], 0)
            n = int(a.args[1], 0) if len(a.args) > 1 else 32
            data = p.dump(addr, n)
            for off in range(0, len(data), 16):
                ch = data[off:off + 16]
                hx = " ".join("%02x" % c for c in ch)
                asc = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in ch)
                print("%08x  %-47s  %s" % (addr + off, hx, asc))
    except PineError as e:
        sys.exit("PINE error: %s" % e)


if __name__ == "__main__":
    main()
