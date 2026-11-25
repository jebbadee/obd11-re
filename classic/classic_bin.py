"""Binary-dialect probes over RFCOMM: adapter-local frames only, long RX windows."""
import socket
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
from probe import crc16, deframe, extcmd, frame_binary, hx, unscramble  # noqa: E402

PROBES = [
    ("proto select Null [20 00] plain", frame_binary(b"\x20\x00")),
    ("proto select Null [20 00] scrambled", frame_binary(b"\x20\x00", scrambled=True)),
    ("ExtCmd health plain", frame_binary(b"\x7e" + extcmd(2, 0x2A))),
    ("ExtCmd health scrambled", frame_binary(b"\x7e" + extcmd(2, 0x2B), scrambled=True)),
]


def main(mac, channel=1):
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    s.settimeout(12)
    s.connect((mac, channel))
    print("connected")
    s.settimeout(0.5)

    def drain(seconds):
        buf, end = b"", time.time() + seconds
        while time.time() < end:
            try:
                chunk = s.recv(512)
                if not chunk:
                    print("   (peer closed)")
                    break
                buf += chunk
                if buf.endswith(b"\x04"):
                    end = min(end, time.time() + 0.7)
            except socket.timeout:
                continue
            except OSError as e:
                print(f"   recv error: {e}")
                break
        return buf

    print(f"idle 3s: {hx(drain(3))}")
    for label, data in PROBES:
        s.send(data)
        raw = drain(7)
        print(f"{label}\n   TX={hx(data)}\n   RX={hx(raw)}")
        for f in deframe(raw):
            body, tail = f[:-2], f[-2:]
            ok = len(f) > 2 and crc16(body) == tail[0] | tail[1] << 8
            print(f"   frame={hx(f)} crc_ok={ok} unscrambled={hx(unscramble(body)) if body else ''}")
    s.close()


main(sys.argv[1])
