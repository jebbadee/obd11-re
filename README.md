# OBDeleven ("OBD11") adapter — reverse engineering + Linux probe

Protocol findings for the OBDeleven OBD11 Bluetooth-Low-Energy OBD2 dongle (VW/Audi group focus),
extracted from the official Android app `com.voltasit.obdeleven.basic` v2.16.0 (versionCode 419),
plus a ready-to-run Python/bleak driver probe.

Not affiliated with OBDeleven/Voltasit. Analysis of their freely distributed APK for
interoperability; the APK itself and the toolchain are not redistributed here.

## Start here

- `REPORT.md` — the full protocol spec, ~60 file:line evidence citations from the decompiled
  app, open questions, reproducible extraction method.
- `probe.py` — BLE scan → dongle-family classifier → live handshake
  (legacy ASCII `AT RV` exchange or Gen3 framed protobuf request). Requires
  [bleak](https://github.com/hbldh/bleak) (`pip install bleak`), a BlueZ adapter, and the dongle
  plugged into the car with ignition ON.

```
python3 probe.py --selftest      # offline primitive checks (no hardware needed)
python3 probe.py                 # scan, classify, handshake
python3 probe.py --mode gen2 --send "07 02"     # read VIN on a legacy-family dongle
python3 probe.py --mac AA:BB:CC:DD:EE:FF --seconds 8
```

## Protocol in 10 seconds

- BLE only; no pairing/bonding, plaintext GATT; writes chunked to 19 bytes (app never negotiates MTU).
- Legacy family: write characteristic prefix `0000fff2` (fallback custom `bef8d6c9...`), notify `0000fff1`.
  ASCII dialect `"service pid\r"` terminated by `\r>` prompt — e.g. `03`/`04` DTC ops,
  `07 02` VIN, `01 A6` mileage, `AT RV` battery. Hex-text response lines.
- Gen3 family: service `0000ffe0` / char `0000ffe1` (firmware mode `ffe3`/`ffe4`). Binary framing:
  optional XOR scramble + CRC-16/XMODEM (low byte first) + SLIP `0F...04` escapes; envelope
  `0x7E` + protobuf `ExtCmd{id, transactionId, payload}`.
- VW diagnostics dialects on the binary channel: transport setup `[0x20][protoId]`, ISO-TP/UDS as
  `[0x21][2-byte LE length][UDS PDU]` (VIN = `22 F1 90`), VAG 29-bit addressing
  `18DA<addr>F1` <-> `18DAF1<addr>` with the adapter at node `0xF1`; KWP2000/K-line TP2.0 headers
  with additive checksum, `7F xx 78` pending handling, `3E` tester-present keep-alive.

## Files

| path | what |
|---|---|
| `REPORT.md` | full RE report (protocol, evidence, open questions, method) |
| `probe.py` | bleak driver/probe, selftesting (11 vectors: CRC, SLIP, scramble, protobuf, deframer) |
| `references/extraction-gen2-kline.log` | working transcript: ASCII dialect + KWP2000/K-line extraction |
| `references/extraction-gen3-binary.log` | working transcript: Gen3 binary/protobuf + UDS extraction |
| `LICENSE` | MIT for `probe.py`; report text dedicated to CC0 (see LICENSE header note) |

## Reproducing the pipeline (Linux)

```
# APK (goopdl: Play Store CLI, anonymous auth)
goopdl download com.voltasit.obdeleven.basic -o apks --splits --arch arm64 -c US -v 419
# decompile (JRE 17 + jadx 1.5.1; the --show-bad-code pass is REQUIRED:
# without it, Kotlin-coroutine method bodies — where the protocol logic lives — are lost)
JAVA_HOME=tools/jre17 tools/jadx/bin/jadx -j 4 --no-res --no-debug-info --show-bad-code -d jadx_out2 apks/com.voltasit.obdeleven.basic-419.apk
```

## Status

Protocol layers above are code-verified against the app. Live-hardware items still open (dongle
plugged in, ignition ON): which family a given physical unit advertises, whether binary frames
share `fff1`/`fff2` with ASCII on legacy units, device-side reply framing details, extended vendor
AT set. See `REPORT.md` section 7.
