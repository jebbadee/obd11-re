"""Characterise what triggers the dongle's 0F reply. Adapter-local bytes only."""
import socket
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
from probe import crc16, hx, slip_wrap  # noqa: E402

inner = b"\x20\x00"
c = crc16(inner)
PROBES = [
    ("single 0F", b"\x0f"),
    ("single 04", b"\x04"),
    ("single 00", b"\x00"),
    ("0F 04 (empty frame)", b"\x0f\x04"),
    ("[20 00] CRC high-first", slip_wrap(inner + bytes([c >> 8, c & 0xFF]))),
    ("[20 00] no CRC", slip_wrap(inner)),
    ("[20 00] raw unframed", inner),
    ("[20 00] CRC low-first (report)", slip_wrap(inner + bytes([c & 0xFF, c >> 8]))),
]


def main(mac):
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    s.settimeout(12)
    s.connect((mac, 1))
    s.settimeout(0.3)

    def drain(seconds):
        buf, t0, stamps, end = b"", time.time(), [], time.time() + seconds
        while time.time() < end:
            try:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk
                stamps.append(round(time.time() - t0, 2))
            except socket.timeout:
                continue
        return buf, stamps

    print("idle:", drain(2))
    for label, data in PROBES:
        s.send(data)
        raw, stamps = drain(4)
        print(f"{label:34s} TX={hx(data):16s} RX={hx(raw)} at={stamps}")
    s.close()


main(sys.argv[1])
