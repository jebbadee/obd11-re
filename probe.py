#!/usr/bin/env python3
"""OBDeleven ("OBD11") BLE adapter probe — classify + handshake per RE report (~/obd11-re/REPORT.md).

Selftest (no hardware):  python3 probe.py --selftest
Live scan+handshake:     python3 probe.py [--seconds 12] [--mac XX:..] [--mode auto|gen2|gen3]
                         [--send '07 02' | --send-hex 0f2103000022f19004] [--at RV]
Requires bleak (pip install --target $(python3 -c 'import site;print(site.getsitepackages()[0])') bleak).
"""
import argparse, asyncio, binascii, random, struct, sys

# ---------- primitives (all from decompiled app evidence) ----------

def crc16(data: bytes) -> int:
    """CRC-16 poly 0x1021, init 0x0000, MSB-first, no final xor (= CRC-16/XMODEM check family)."""
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def slip_wrap(payload: bytes) -> bytes:
    out = bytearray([0x0F])
    for b in payload:
        if b in (0x04, 0x05, 0x0F):
            out.append(0x05)
            out.append(b)
        else:
            out.append(b)
    out.append(0x04)
    return bytes(out)

def scramble(data: bytes, seed: int | None = None):
    """Prepend seed byte (random, high bit set); xor each byte with running key d, d rotates (d>>1)|(d<<7)."""
    d = seed if seed is not None else random.randrange(128, 256)
    out = bytearray([d])
    for b in data:
        out.append(b ^ d)
        d = ((d >> 1) | (d << 7)) & 0xFF
    return bytes(out)

def unscramble(packed: bytes) -> bytes:
    d = packed[0]
    out = bytearray()
    for b in packed[1:]:
        out.append(b ^ d)
        d = ((d >> 1) | (d << 7)) & 0xFF
    return bytes(out)

def frame_binary(inner: bytes, scrambled: bool = False) -> bytes:
    """TX chain per core_communication/providers/a.a(...): [scramble] + CRC16(low-first) + SLIP + caller chunks to 19B."""
    body = scramble(inner) if scrambled else inner
    c = crc16(body)
    body += bytes([c & 0xFF, c >> 8])           # low byte first (evidence)
    return slip_wrap(body)

def deframe(stream: bytes):
    """RX state machine per defpackage/mi7.java: 0x0F/0x04 delimit frames, 0x05 escapes next byte."""
    frames, cur, esc = [], bytearray(), False
    for b in stream:
        if esc:
            cur.append(b); esc = False; continue
        if b == 0x0F:
            cur = bytearray(); continue          # start (also 'discard partial' variant on mid-stream 0F)
        if b == 0x04:
            if cur: frames.append(bytes(cur))
            cur = bytearray(); continue
        if b == 0x05:
            esc = True; continue
        cur.append(b)
    return frames

def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def extcmd(cmd_id: int, txn: int, payload: bytes = b"", req_type: int = 0) -> bytes:
    """kotlinx-protobuf ExtCmd{id=1,type=2,transactionId=3,payload=4}; proto3 defaults omitted (type=0 omitted)."""
    out = b"\x08" + varint(cmd_id) + b"\x18" + varint(txn)
    if payload:
        out += b"\x22" + varint(len(payload)) + payload
    return out

def proto_fields(blob: bytes):
    """Minimal protobuf field walker: yields (field_no, wire_type, value)."""
    i = 0
    while i < len(blob):
        try:
            key = blob[i]; i += 1
            fno, wt = key >> 3, key & 7
            if wt == 0:
                v = 0; shift = 0
                while True:
                    b = blob[i]; i += 1
                    v |= (b & 0x7F) << shift
                    if not b & 0x80: break
                    shift += 7
                yield fno, wt, v
            elif wt == 2:
                ln = 0; shift = 0
                while True:
                    b = blob[i]; i += 1
                    ln |= (b & 0x7F) << shift
                    if not b & 0x80: break
                    shift += 7
                yield fno, wt, blob[i:i + ln]; i += ln
            elif wt == 5:
                yield fno, wt, blob[i:i + 4]; i += 4
            elif wt == 1:
                yield fno, wt, blob[i:i + 8]; i += 8
            else:
                return
        except IndexError:
            return

def hx(b): return binascii.hexlify(b).decode().upper()

# ---------- legacy ASCII dialect ----------

ASCII_TX = lambda service, pid: (f"{service} {pid}" if pid else f"{service} ").encode() + b"\r"

def ascii_clean(raw: bytes, echo: str = "") -> bytes:
    """gy0.b0-lite: strip leading '>' prompt, strip 5-char 'ATxxx' echo, split on \r, dedupe
    keep-first (case-insensitive), keep hex-only data lines (spaces/colons tolerated), odd nibble
    count left-pads '0', hex-decode. Status lines (OK/NO DATA/…) are non-hex so they drop out."""
    text = raw.decode("utf-8", "replace")
    if text.startswith(">"):
        text = text[1:]
    if text.startswith("AT"):
        text = text[5:]
    seen, data, echo_norm, echo_done = set(), "", echo.replace(" ", "").upper(), False
    for l in text.split("\r"):
        cand = l.strip().lstrip(">").replace(" ", "").replace(":", "").upper()
        if not cand:
            continue
        if echo and not echo_done and cand == echo_norm:   # drop the echoed request line once
            echo_done = True
            continue
        k = cand.lower()
        if k in seen:
            continue
        seen.add(k)
        if all(c in "0123456789ABCDEF" for c in cand):
            data += cand
    if len(data) % 2:
        data = "0" + data
    try:
        return binascii.unhexlify(data) if data else raw
    except binascii.Error:
        return raw

# ---------- live (bleak) ----------
SERVICE_HINTS = ("0000ffe0", "0000ffe3", "0000fff0", "0000fff1", "bef8d6c9")

def classify(services):
    """services: dict char_uuid_prefix -> {'write','notify'} gathered from GATT. Returns 'gen2'|'gen3'."""
    if any(u.startswith("0000fff") for u in services) or any(u.startswith("bef8d6c9") for u in services):
        return "gen2"
    if any(u.startswith("0000ffe") for u in services):
        return "gen3"
    return "unknown"

async def live(args):
    from bleak import BleakClient, BleakScanner
    print(":: scanning…")
    devices = await BleakScanner.discover(timeout=args.seconds)
    picks = []
    for d in devices:
        name = (d.name or "").lower()
        uuids = [u.lower() for u in (d.service_uuids or [])]
        if args.mac and d.address.lower() != args.mac.lower():
            continue
        if (args.mac or any(h in u for u in uuids for h in SERVICE_HINTS)
                or "obd" in name or "eleven" in name or "voltasit" in name):
            picks.append(d)
    if not picks:
        print(":: no OBDeleven-like device found. Plug the dongle in, ignition ON, and re-run.")
        for d in devices:
            print(f"   seen: {d.address} {d.name!r} {d.service_uuids}")
        return
    for d in picks:
        print(f":: target {d.address} name={d.name!r} advertised={[u for u in (d.service_uuids or [])]}")
        async with BleakClient(d.address if hasattr(d, "address") else d, timeout=20.0) as c:
            await probe_client(c, args)

RX = asyncio.Queue()

async def probe_client(client, args):
    # dump GATT
    chars = {}
    for s in client.services:
        for ch in s.characteristics:
            chars[ch.uuid.lower()] = ch
            print(f"   svc {s.uuid}  char {ch.uuid} props={ch.properties}")
    mode = args.mode
    tx = rx = None
    def pick(prefixes, prop):
        for u, ch in sorted(chars.items()):
            if any(u.startswith(p) for p in prefixes):
                return ch
        return None
    if mode in ("auto", "gen2"):
        tx = tx or pick(("0000fff2", "bef8d6c9"), "write")
        rx = rx or pick(("0000fff1",), "notify")
        if tx and rx:
            mode = "gen2"
    if mode in ("auto", "gen3") and (not tx or not rx):
        tx = tx or pick(("0000ffe1",), "write")
        rx = rx or pick(("0000ffe1",), "notify")
        if tx and rx:
            mode = "gen3"
    print(f":: mode={mode} tx={tx and tx.uuid} rx={rx and rx.uuid}")
    if not (tx and rx):
        print(":: could not resolve characteristics — dump above, report to RE notes.")
        return
    got_any = asyncio.Event()
    def _cb(_ch, data):
        RX.put_nowait(bytes(data)); got_any.set()
    await client.start_notify(rx, _cb)  # bleak writes CCCD 00002902 itself

    async def collect(until, timeout=8.0):
        buf = b""
        try:
            while True:
                buf += await asyncio.wait_for(RX.get(), timeout)
                if until(buf):
                    return buf
        except asyncio.TimeoutError:
            return buf

    async def send(payload, chunk=19, gap=0.02):
        for i in range(0, len(payload), chunk):
            await client.write_characteristic(tx, payload[i:i + chunk],
                                              response="write" in tx.properties)
            await asyncio.sleep(gap)

    if mode == "gen2":
        if args.send_hex:
            payload = binascii.unhexlify(args.send_hex.replace(" ", ""))
            label = args.send_hex
        else:
            s, _, pid = (args.send or "AT RV").partition(" ")
            payload = ASCII_TX(s, pid)
            label = payload
        print(f":: TX {label!r} hex={hx(payload)}")
        await send(payload)
        raw = await collect(lambda b: b.endswith(b">") or b.endswith(b"\r>") or b.endswith(b"\n>"), args.timeout_s)
        text = raw.decode("utf8", "replace")
        print(f":: RX raw hex={hx(raw)}")
        print(f":: RX text={text!r}")
        if raw:
            print(f":: decoded={hx(ascii_clean(raw, s + pid))}")
    else:
        txn = 0x2A
        if args.send_hex:
            inner = binascii.unhexlify(args.send_hex.replace(" ", "")); label = args.send_hex
        else:
            inner = b"\x7e" + extcmd(2, txn)  # GET_HEALTH_STATUS default id
            label = f"ExtCmd id=2 txn={txn:#x}"
        framed = frame_binary(inner, scrambled=False)
        print(f":: TX {label} inner={hx(inner)} framed={hx(framed)}")
        await send(framed)
        raw = b""
        async def got(b): return len(deframe(b)) > 0
        raw = await collect(got, args.timeout_s)
        frames = deframe(raw)
        print(f":: RX raw hex={hx(raw)} frames={[hx(f) for f in frames]}")
        for f in frames:
            for off, tag in ((1, "strip-seed"), (2, "gen3-strip2"), (0, "as-is")):
                body = f[off:]
                fields = list(proto_fields(body))
                if fields and fields[0][0] in (1, 2, 3):
                    print(f"   frame({tag}) fields: {[(n, t, (v.hex().upper() if isinstance(v, bytes) else v)) for n, t, v in fields]}")
                    break
            else:
                print(f"   frame unparsed: {hx(f)}")
    await client.stop_notify(rx)

def selftest():
    ok = True
    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok &= good
        print(f"[{'ok' if good else 'FAIL'}] {name}: {got!r} (want {want!r})")
    chk("crc16 XMODEM vector", hex(crc16(b"123456789")), hex(0x31C3))
    chk("slip", hx(slip_wrap(b"\x01\x04\x05\x0f")), "0F0105040505050F04")
    s = scramble(b"\x7e\x08\x02\x18\x2a", seed=0x81)
    chk("scramble reversible", unscramble(s), b"\x7e\x08\x02\x18\x2a")
    chk("extcmd proto", hx(extcmd(2, 0x2A)), "0802182A")
    chk("extcmd with payload", hx(extcmd(0, 7, b"\xaa")), "0800180722 01AA".replace(" ", ""))
    f = deframe(slip_wrap(b"\x7e\x08\x02\x18\x2a" + bytes([crc16(b"\x7e\x08\x02\x18\x2a") & 0xFF, 0])) )
    chk("deframe roundtrip", [hx(x) for x in f], [hx(b"\x7e\x08\x02\x18\x2a" + bytes([crc16(b'\x7e\x08\x02\x18\x2a') & 0xFF, 0]))])
    chk("ascii TX", ASCII_TX("AT", "RV"), b"AT RV\r")
    chk("ascii TX pidless", ASCII_TX("04", ""), b"04 \r")
    chk("ascii_clean", hx(ascii_clean(b">AT RV\rOK\r12\r>")), "12")
    chk("ascii_clean multiline", hx(ascii_clean(b">0702\r46 31 30 31\r48 44 30\r>", "0702")), "46313031484430")
    chk("frame_binary determinism", hx(frame_binary(b"\x7e\x08\x02\x18\x2a")),
        "0F" + hx(b"\x7e\x08\x02\x18\x2a" + bytes([crc16(b"\x7e\x08\x02\x18\x2a") & 0xFF, crc16(b"\x7e\x08\x02\x18\x2a") >> 8])) + "04")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--seconds", type=int, default=12)
    ap.add_argument("--mac", default=None)
    ap.add_argument("--mode", choices=["auto", "gen2", "gen3"], default="auto")
    ap.add_argument("--send", default=None, help="legacy ASCII command as 'service pid' (default 'AT RV')")
    ap.add_argument("--send-hex", default=None, help="raw TX bytes hex (framed-binary for gen3 mode, raw for gen2)")
    ap.add_argument("--timeout-s", type=float, default=8.0, help="response wait per exchange")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    try:
        import bleak  # noqa
    except ImportError:
        print("bleak missing: pip install --target $(python3 -c 'import site;print(site.getsitepackages()[0])') bleak")
        sys.exit(2)
    asyncio.run(live(args))

if __name__ == "__main__":
    main()
