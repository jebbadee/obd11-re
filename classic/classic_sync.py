"""Test whether the 0F echo is a ready-handshake: sync first, then send the frame body.

Adapter-local payloads only ([20 00] = select "no protocol", ExtCmd health).
Usage: python classic_sync.py <MAC>
"""
import socket
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
from probe import crc16, deframe, extcmd, frame_binary, hx  # noqa: E402


def open_link(mac, channel=1):
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    s.settimeout(12)
    s.connect((mac, channel))
    s.settimeout(0.2)
    return s


def drain(s, seconds, stop_on=None):
    buf, t0, stamps, end = b"", time.time(), [], time.time() + seconds
    while time.time() < end:
        try:
            chunk = s.recv(512)
            if not chunk:
                break
            buf += chunk
            stamps.append(round(time.time() - t0, 2))
            if stop_on and buf.endswith(stop_on):
                break
        except socket.timeout:
            continue
        except OSError as e:
            print(f"   recv error: {e}")
            break
    return buf, stamps


def main(mac):
    s = open_link(mac)
    print("idle:", drain(s, 1.5))
    for name, inner in (("[20 00]", b"\x20\x00"), ("ExtCmd health", b"\x7e" + extcmd(2, 0x31))):
        frame = frame_binary(inner)
        rest = frame[1:]                      # everything after the leading 0F

        s.send(b"\x0f")
        echo, _ = drain(s, 1.5, stop_on=b"\x0f")
        s.send(rest)
        raw, st = drain(s, 5)
        print(f"A {name}: sync echo={hx(echo)}; then body {hx(rest)} -> RX={hx(raw)} at={st} frames={[hx(f) for f in deframe(raw)]}")

        s.send(b"\x0f")
        echo, _ = drain(s, 1.5, stop_on=b"\x0f")
        s.send(frame)
        raw, st = drain(s, 5)
        print(f"B {name}: sync echo={hx(echo)}; then full frame {hx(frame)} -> RX={hx(raw)} at={st}")

        for b in frame:                       # slow, byte at a time
            s.send(bytes([b]))
            time.sleep(0.03)
        raw, st = drain(s, 5)
        print(f"C {name}: byte-by-byte 30ms -> RX={hx(raw)} at={st}")

        s.send(frame)                         # echo our own 0F back if the dongle opens a frame
        raw, st = drain(s, 1.5, stop_on=b"\x0f")
        s.send(b"\x0f")
        raw2, st2 = drain(s, 5)
        print(f"D {name}: frame -> {hx(raw)}; we answer 0F -> RX={hx(raw2)} at={st2}")
    c = crc16(b"")
    print("crc(empty)=", hex(c))
    s.close()


main(sys.argv[1])
