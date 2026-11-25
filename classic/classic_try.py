"""Send several adapter-local probes over RFCOMM and print whatever comes back."""
import socket
import sys
import time

PROBES = [
    ("ATZ CR", b"ATZ\r"),
    ("ATI CR", b"ATI\r"),
    ("AT RV CR", b"AT RV\r"),
    ("ATRV CRLF", b"ATRV\r\n"),
    ("gen3 ExtCmd health (framed)", bytes.fromhex("0F7E0802182A7F3604")),
    ("bare CR", b"\r"),
]


def main(mac: str, channel: int):
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    s.settimeout(12)
    s.connect((mac, channel))
    print(f"connected channel {channel}")
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
            except socket.timeout:
                continue
            except OSError as e:
                print(f"   recv error: {e}")
                break
        return buf

    b = drain(2)
    print(f"banner: hex={b.hex().upper()} text={b!r}")
    for label, data in PROBES:
        try:
            s.send(data)
        except OSError as e:
            print(f"{label}: send failed: {e}")
            break
        b = drain(3)
        print(f"{label}: TX={data.hex().upper()} RX hex={b.hex().upper()} text={b!r}")
    s.close()


main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 1)
