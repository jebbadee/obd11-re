# OBDeleven ("OBD11") adapter — reverse-engineering report
App: OBDeleven basic, com.voltasit.obdeleven.basic v2.16.0 (versionCode 419), arm64, downloaded via goopdl (anonymous Play auth).
Inputs: official APK + full jadx decompile (21k classes, two passes: default and `--show-bad-code`).
Paths: `~/obd11-re/apks/`, `~/obd11-re/jadx_out2/sources/` (better pass), `~/obd11-re/allstrings.txt`.
All `file:line` citations below are relative to `jadx_out2/sources/` unless stated. "V" = verified in code, "H" = hypothesis.

---

## 0. TL;DR — talking to the dongle from Linux

Two BLE protocol families coexist in the app:

- LEGACY family ("basic/Gen1-Gen2 dongles"): BLE service 0xFFF0-ish. GATT characteristics: write → UUID prefix `0000fff2` (fallback `bef8d6c9…`), notify → prefix `0000fff1` (CCCD 00002902 = ENABLE). No bonding, no encryption, no MTU negotiation (fixed 20-byte ATT payloads). TX = ASCII `"service pid\r"` (space-joined, UTF-8), RX = accumulate notifications until the joined text ends with `"\r>"` (ELM327 prompt), then drop the leading `>` byte.
- GEN3 family ("newer adapters"): BLE service `0000ffe0` + characteristic `0000ffe1` (update/firmware mode: service `0000ffe3`/char `0000ffe4`, chosen by a flag in the scan filter, v.java:420). Binary framing: SLIP-style (`0F … 04`, escape 04/05/0F → 05 xx) + CRC-16 (poly 0x1021, init 0x0000, appended LOW byte first) + optional XOR-descramble (seed byte prepended, rotate-right 1 / left 7) + fixed 19-byte ATT chunks, WRITE_TYPE_DEFAULT. Payload envelope: `0x7E` + kotlinx-serialization **protobuf** ExtCmd `{id=1,type=2,transactionId=3,payload=4}`; only 4 "passive diag" ExtCmdIds exist.
- Diagnostics dialect on the binary channel is NOT raw ELM327: ISO-TP/UDS frames are sent as `[0x21][len LE 2 bytes][UDS PDU]`, replies have their first 2 bytes stripped (`common/q.java:455,465`); transport-protocol setup is `[0x20][protoId]` → ACK `[0x20][0x00]` (`common/l0.java`). KWP2000-over-K-line has its own TP2.0 framing (§4).
- CAN ids (V, from enums): engine 0x7E0→0x7E8, trans 0x7E9; VAG 29-bit physical = `0x18DA<addr>0xF1` request → `0x18DAF1<addr>` response (adapter node address = **0xF1**, `defpackage/rca.java:13`). Dashboard 0x714→0x77E (`models/vag/VagUdsTarget.java`).

A ready probe script (scan→classify→handshake→`AT RV`/health-request) is `~/obd11-re/probe.py`.

---

## 1. Adapter generations / families (V for code structure, H for which hardware maps where)

- The app ships **three command stacks** over ONE BLE GATT abstraction:
  1. `Elm327*` stack — ASCII `"S S\r"` dialect (shared/providers/{d,e}.java, data/callbacks/a.java). Generic-OBD use-cases only (DTCs, VIN, mileage, readiness, battery).
  2. Native "obdeleven/KWP" stack — binary K-line/TP2.0/KWP2000 commands (core_communication/commands/kline/, obd2_communication/usecase/obdeleven/) with dedicated setup/IoCtl frames.
  3. Gen3 protobuf stack — passive-diag ExtCmds + IsoTp/UDS over the framed binary channel (core_communication/commands/{gen3,common}/, usecase/uds, usecase/kwp).
- `BluetoothDataTransferProviderImpl` (core_communication/providers/a.java, V) implements BOTH ASCII text passthrough (`a(String…, delimiter…)`) and framed binary (`a(byte[], z, z2)` — scramble/CRC/SLIP) — i.e. the newer adapters can carry both dialects on one GATT profile. H: legacy FFF0-style adapters speak dialects 1+2 on FFF1/FFF2; Gen3 adapters speak 2+3 on FFE1. Which vendor HW corresponds to FFF0 vs FFE0 vs bef8d6c9 is UNRESOLVED without a live scan — probe.py classifies empirically.
- Firmware/update mode: dedicated GATT `0000ffe3`+`0000ffe4`, "boot mode" connect failure strings in v.java:952/1050; firmware write procedure `startFirmwareWriteProcedure` v.java:553-587; `StuckFirmwareException` exists (leBluetoothProvider/a.java:515).
- Legacy classic-BR/EDR (SPP) transport strings (`createRfcommSocket`) exist in the APK strings dump — H: Gen1 "Classic" dongles are SPP ELM327; on Linux: `sudo rfcomm bind 0 <MAC> 1` then same ASCII dialect over /dev/rfcomm0. UNVERIFIED.

## 2. BLE access layer (V, both families)

- Connect: `connectGatt(ctx, autoConnect=FALSE, cb, TRANSPORT_LE=2)` (leBluetoothProvider/a.java:155, data/callbacks/a.java:101). Retries log "Resuming connectGatt()".
- Pairing/bonding: **none anywhere** on the data path (zero createBond/BOND hits in v.java, callbacks/a.java, providers/d.java, leBluetoothProvider/a.java). JustWorks, plaintext GATT.
- Notifications: `setCharacteristicNotification(ch,true)` + write descriptor `00002902-…` = ENABLE_NOTIFICATION_VALUE, suspend until `onDescriptorWrite` (data/callbacks/a.java:393-409; leBluetoothProvider/a.java:205-221; v.java:472,1432).
- Write type: `writeCharacteristic(ch, data, 1)` = WRITE_TYPE_DEFAULT (API≥33 path; data/callbacks/a.java:254, v.java:1077).
- MTU: `requestMtu` appears NOWHERE in the app — never negotiates; TX chunking is fixed 19-byte pieces (`vc1.f(19, frame)` → channel → one write per chunk). So a Linux driver must chunk to ≤20-byte writes (or ≤19 to match the vendor client).
- RX buffer: 20480 bytes; overflow log "Buffer is full, unable to send bluetooth data to observers" (defpackage/mi7.java).

## 3. Legacy ASCII dialect (ELM327-ish, V)

TX construction (shared/providers/e.java, V):
- `Elm327Command(service,pid)` (defpackage/l74.java) → UTF-8 text = `service + " " + pid` joined with space + `"\r"`. (Empty pid yields trailing space — whether tolerated, UNRESOLVED; pid-less commands observed as `("04","")`.)
- Write path selects characteristic: first whose UUID string startsWith `0000fff2`, else `bef8d6c9`, else throw "No write characteristic" (data/callbacks/a.java:222/237/244). Notify characteristic: startsWith `0000fff1`, else a mutable static prefix `hBICm.Kfy` with no decompiled assignment (UNRESOLVED; likely a bef8d6c7-family UUID) (callbacks/a.java:354/369/377).

RX acceptance (data/callbacks/a.d, V):
- Append every notification; when joined text ENDS WITH `"\r>"` → log "ELM327 command response:", resume with accumulated bytes minus the FIRST byte (strip leading `>`), clear buffer (callbacks/a.java:274-292). Multi-notification responses OK. No BLE-level timeout (unbounded continuation); command layer adds withTimeout under a GLOBAL mutex (commands/b.java:67-118 — every command serialized fleet-wide).
- Cleaner `gy0.b0` (defpackage/gy0.java:791-845): UTF-8 decode; if text startsWith "AT" → drop first 5 chars (echo strip); "NO DATA" → NoDataException; split on `"\r"`, drop blanks, dedupe keep-first (case-insensitive); keep hex-data lines (regex `.`+`:` region, semantics fuzzy), odd nibble count → prepend "0"; hex-decode; on multiple lines take LAST match first then remaining alnum. Net effect: adapter answers with **uppercase hex text lines, prompt-terminated**.

Full catalog the app actually sends (V, exhaustive tree grep for `new l74(`):
- `("04","")` clear DTCs; `("03","")` stored DTCs; `("0A","")` permanent DTCs; `("07","0A")` readiness-ish probe; `("07","02")` VIN read (ReadVinObd2ElmUC); `("01","A6")` mileage (ReadMileageObd2ElmUC); **`("AT","RV")`** battery voltage → wire `AT RV\r` (elm/{a,b,c,d,e,f}.java; service token = 2-digit uppercase hex of Obd2Service byte 1/3/4/7/9/10, plus literal "AT").
- NOTE: `07 02`/`01 A6` are NOT standard ELM327 spellings — the dongle firmware has its own parsing; treat this as "OBDeleven ASCII dialect", ELM327-flavored. Vendor AT-set beyond "AT RV": UNRESOLVED (no ATZ/ATDP/ARA literals anywhere).

## 4. Native diagnostic dialect (K-line / KWP2000 / CAN, V unless noted)

Transport enum ids (core_communication/model/TransportationProtocol.java, V): Null=00, Can=01, IsoTp=02, Tp20=03, Tp16=04, KLine=05, IsoTpObd2=06, AutoDetect=07.

Setup sequence for VW K-line (Obd2ConnectKlineUC, V):
1. K-Line IoCtl frame payload `22 00 33` (`{0x22,flag} ++ {0x33}`, kline/b.java:41); accept: resp[0]==0x22; resp[1]!=0 → CommandException(resp[1]); short resp error "K-Line IoCtl response too short".
2. Protocol select: `[0x20][protoId]` (e.g. Tp20→`20 03`), success iff exact `[0x20][0x00]` (kline path twin of common/l0.java), two 3000 ms windows (kline/d.java:205,216); a 55 ms step exists in the flow (obdeleven/e.java:275).
3. Keep-alive loop (Obd2KlineKeepAliveController, obd2_communication/session/a.java): every ~1000 ms send ISO9141 `{01 00}` (ordinal 2) or KWP functional `{3E}` tester-present (ordinal 3) (session/a.java:23-24,126-138).

TP2.0 (KWP2000) frame builder (KLineKwp2000RequestCommand, kline/c.java:184-199, V):
- payload len ≤255 (guard literal "payload length must be <= 255");
- header: `[0x80|len , 0x33, 0xF1]` (physical) or `[0xC0|len , …]` (functional) for len ≤63; if 64..255: `[hdr, 0x33, 0xF1, len]` — **length is low 6 bits / trailing explicit byte, NOT a 16-bit pair**; `0x33 0xF1` = fixed addresses (target service-area 33? adapter F1; every call site passes literal 51=0x33 as serviceId — semantics UNRESOLVED);
- then payload, then **simple additive checksum** (running sum & 0xFF appended).
- RX: swallow NRC-pending frames `7F xx 78` and keep collecting (…performRequest$2.java:102/:78); on stream end: empty buffer → hex-decode result, else TimeoutException.
- NRC policy (V, kline/c.java:323-360): busy-type NRC 0x21/0x23 → retry up to 3 attempts with `delay(1000 ms)`; NRC 0x78 → wait indefinitely; malformed NRC → "NRC message must have at least 3 bytes". Nrc enum catalogs 0x10…0x78/0x81 (Nrc.java:39-75).
- Fault clearing (ClearAllObd2FaultsUC, obdeleven/a.java): K-line step1 `i.a(51, true)` (serviceId 0x33 hardwired everywhere), step2 functional broadcast `[C1…] 33 F1 04 + cksum` via oh9; CAN twin `clearOnCan` exists.
- CAN responder probe (FindObd2ReadinessCuAddressUC.getResponderAddresses, obdeleven/b.java:95-128): collect functional responders, keep those in ResponseCan enum {Engine=0x7E8, EngineVolvo29Bit, EngineVag29Bit, EngineMercedes29bit, Transmission=0x7E9}.

ISO-TP/UDS dialect on the framed binary channel (Gen3-era, V):
- TX: `[0x21][len LO][len HI][UDS PDU]` (common/k0.java:39-53 — 2-byte LITTLE-endian length); RX: drop first 2 bytes (common/q.java mapResponse).
- Setup `[0x20][protoId]`; broadcast setup `[0x22][0x01|0x02][flags…]+CAN-id list` (SetupBroadcastUC, usecase/c.java:92-123).
- Example payloads: read DID = `[0x22][DID BE]` (usecase/uds/i.java VagReadDataByIdRequestUC:45-52, e.g. 22 F1 90 = VIN; kwp twin usecase/kwp/b.java sends `[0x22]+2-byte common id` via dc7 interface).

## 5. Gen3 binary envelope (V per citations)

- BaseProtobufCommand (gen3/a.java, proven by coroutine metadata): TX = `d20.s({0x7E}, protobuf(ExtCmd{id=f(), transactionId=c, payload=d()}))` (a.java:110-116); RX matcher: byte0==0x7E, **drop first 2 bytes**, decode ExtCmd, require transactionId+id match (a.java:66-90); error frames: after the same 2-byte strip, if next==0x7E and LAST byte !=0 → CommandException(errorCode) (a.java:55-62).
- ExtCmdId (model/proto/ExtCmdId.java:31-35): PASSIVE_DIAG_SET_CFG(0), SET_ECU_LIST(1), GET_HEALTH_STATUS(2), GET_LIVE_DATA(3) — protobuf channel carries ONLY passive diagnostics; live diagnostic requests use the IsoTp dialect above. ExtCmdType REQUEST=0/RESPONSE=1; ProtoCmdResult OK=0/NOK=1.
- Serialization: kotlinx-serialization **protobuf plugin** (definitive: r1b.java imports kotlinx.serialization.protobuf.internal.{a,b}; 30 protobuf imports; descriptor builder qna.java with @ProtoNumber annotations). Field tables: ExtCmd id=1,type=2,transactionId=3,payload=4(bytes); PassiveDiagCtrl{ctrl=1,scanPeriod=2,vin=3}; PassiveDiagEcu{ecuId=1,passiveDiagProtocol=2,requestId=3,responseId=4}; HealthStatusRes{protoCmdResult=1, ecuHealthStatusList=2 blob}; EcuHealthStatus{ecuId,dtcsCount,dtcsCrc,status}; LiveData{runTimeSinceEngineStart,fuelTankLevelInput}; DTC{code,frequency}.
- PassiveDiagProtocol enum: OBDII=0, UDS=1, TP20=2, TP16=3, KLINE=4. Default ECU list (rca.java): OBDII pairs 7E0/7E8…7E6/7EE + 29-bit VAG pairs 18DA10F1/18DAF110, 18DA58F1/18DAF158, 18DA59F1, 18DA5AF1 (adapter addr **F1**).
- Transport framing chain (core_communication/providers/a.a(byte[],…), V):
  1. optional XOR scramble (used when caller flag z=true — Gen3 ext cmds scramble=true; IsoTP UDS writes use z=false): seed = (random & 0x7F)|0x80 **prepended**, xor each byte, key rotate `d = (d>>1)|(d<<7)`;
  2. CRC-16 poly 0x1021 init 0x0000 MSB-first no final xor — appended **low byte first** (CRC of "123456789" would be 0x31C3 = CRC-16/XMODEM family);
  3. SLIP wrap `[0F … 04]`, escaping 04→05 04, 05→05 05, 0F→05 0F;
  4. 19-byte chunks → GATT writes. RX: SLIP-unframing state machine in defpackage/mi7.java:177-197 (0x04 = frame end, 0x05 escape-next, 0x0F = discard partial); app does NOT verify CRC nor unscramble on RX (H: device replies are unscrambled and its CRC (if any) sits inside the 2-byte response header stripped before decode — UNRESOLVED).
- Timeouts: per-command `withTimeout` under global mutex (commands/b.java); numeric defaults not pinned in this pass (UNRESOLVED; earlier bytecode dump suggested 5000 ms region).

## 6. App-side feature map worth stealing for VW use

- Basic/free tier still uses: generic OBD ASCII ops (catalog §3), mileage via `01 A6` trick, VIN via `07 02`, battery `AT RV`, K-line/KWP module I/O (session/keep-alive §4), passive-diag Gen3 config (ECU list + health + live data §5).
- Developer console exists (presentation/developeroptions, RequestProtocol enum incl. IsoTp/Tp20/KLine/AutoDetect) — confirms user-configurable dialect selection at runtime, i.e. the dongle accepts these dialects explicitly.

## 7. Open questions to settle with a live capture (do while plugged in, ignition ON)

1. Which service/characteristic UUIDs the physical dongle advertises (FFF0-family vs FFE0-family vs bef8d6c9 custom) — probe.py dumps full GATT + prints classification.
2. Whether native binary frames (§4/§5) ride the SAME FFF1/FFF2 chars as ASCII on legacy dongles (data/callbacks/a is shared for Elm327 text AND native byte[] commands per providers/b wiring — capture will tell).
3. Device-side response framing for binary dialects: CRC present? scrambled? exact meaning of the 2 stripped RX header bytes.
4. Gen2 "basic" dongle: does it accept `[0x21][lenLE][PDU]` ISO-TP (29-bit addressing) or only §3/§4 legacy? (Try probe.py gen3 test on it.)
5. hBICm.Kfy fallback prefix value; 9141/14230 literals; SPP/Gen1 path confirmation (rfcomm bind + `AT RV\r`).
6. Vendor AT extensions: brute-forge `AT Z/AT1/ATL1/ATV1/AT E0/ATDP/ATCP06/ATARA00/ATARA9141…` against a legacy dongle — responses land in hex-text framing so they're cheap to classify.

## 8. Linux driving recipe (bleak)

- scan: filter service uuids 0000ffe0 / 0000ffe3 / 0000fff0 / any 128-bit bef8d6c9*; or full LE scan and match advertising names.
- connect (no pairing!) → start_notify on the notify char (bleak writes CCCD for you) → write in ≤20-byte chunks (response=True if WRITE property present).
- legacy: `write(tx, b"AT RV\r")` → read notifications until text ends `\r>` → strip leading `>`, if starts `AT` drop 5 chars → hex lines → bytes.
- gen3/binary: build `0x7E|protobuf(ExtCmd)`, CRC16-XMODEM low-first, SLIP wrap, 19-byte writes; parse notifications via mi7-equivalent state machine (probe.py implements all of this).
- UDS over gen3 dialect: `21 len_lo len_hi 10 03` (open session), `21 … 22 F1 90` (VIN), functional `21 … 22 F1 90` with broadcast setup per §4; pending = 7F xx 78 → keep reading; tester-present every ~1 s.

## 9. Evidence anchors (spot-check list)

- ASCII join+\r: shared/providers/e.java (out1 bytecode dump L69 "\r", joinToString(" ") L63); providers/d.java (dispatch) ; l74.java:32.
- FFF1/FFF2/2902/bef8d6c9 selection: data/callbacks/a.java:354/369/393-409 (read side), :222/237/254 (write side).
- Terminator \r> + first-byte strip: data/callbacks/a.java:278/288.
- Cleaner: defpackage/gy0.java:791-845. l74 catalog: obd2_communication/usecase/elm/{a..f}.java cited in §3.
- TP20 builder + checksum + NRC policy: commands/kline/c.java:184-199/323-360; keep-alive session/a.java:23-24/126-138; IoCtl kline/b.java:41; select kline/d.java:205 + common/l0.java.
- IsoTp 0x21+lenLE + drop-2: commands/common/k0.java:39-53 + q.java:455/465; DID build usecase/uds/i.java:45-52.
- Gen3 envelope: commands/gen3/a.java:55-62/110-116/140-142; ExtCmdId proto/ExtCmdId.java:31-35; protobuf plugin defpackage/r1b.java + qna.java; framing chain core_communication/providers/a.java + RX mi7.java:177-197; chunking vc1.f(19) v.java path.
- CAN ids: model/ResponseCan.java:26-34; models/vag/VagUdsTarget.java; default ECU list defpackage/rca.java:13.
- No bonding / no MTU / no createBond: greps over v.java, callbacks/a.java, providers/d.java, leBluetoothProvider/a.java (child audits, transcripts: ~/.hermes/cache/delegation/live/deleg_f1c0ed72/task-{0,1}.log).

## 10. Method notes (reproducible)

- APK: `./goopdl download com.voltasit.obdeleven.basic -o apks --splits --arch arm64 -c US -v 419` (goopdl v2.0.3, anonymous).
- Decompile: JRE17 from Adoptium into tools/jre17 (system Java 8 unusable); `jadx -j 4 --no-res --no-debug-info --show-bad-code -d jadx_out2 apks/…419.apk` (~1 min; pass 1 without --show-bad-code loses Kotlin-coroutine method bodies — always do pass 2).
- Strings: `unzip classes*.dex` + `cat dex/*.dex | strings -n 4 > allstrings.txt`; UUID/AT/framing greps. Beware: vendor keywords live inside huge resource blobs (ad.txt 1.5 MB) → useless; the dialect is built at RUNTIME (hex-formatted, enum-driven) — a pure strings scan misses it; source-level greps (joinToString/concat "\r", d20.s byte-array headers, `new l74(`) are what cracked it.

## 11. Older VAG-app line (FirstGen-compatible) — 2026-11-25/26 addendum

- Package `com.voltasit.obdeleven` IS the old VAG-only app (Play: "OBDeleven VAG
  (old)", 0.107.1 vc 10800, still FirstGen-capable). The new multi-brand app
  (`…​.basic`) does not see FirstGen dongles. APK snapshots 0.34.1 / 0.36.0 /
  0.37.1 (Gen1-era, 2021) + 0.107.1 in `apks/` — inventory + caveats:
  `apks/README-apks-here.md`; 95-version timeline: `docs/obdeleven-vag-versions-catalog.md`.
- Those dexes looked "jadx-malformed" for years (obfuscated build). Verified 2026-11-26:
  bodies are byte-intact and **baksmali 2.5.2 disassembles the original APKs cleanly**
  (header slots hold odd values: link_size=0x12345678, map_off=0, endian slot = pointer
  to a scrambled 224-byte tail map; the tail holds 12-byte (type,size,off) triples —
  decoder: `apks/scan_obdeleven.py`). baksmali must be run PER DEX (apk path reads only
  classes.dex). Recipe + outputs (`../out-034-clean`, 16,330 classes) in
  `apks/README-apks-here.md`; jars in `apks/jars/` (Maven Central).
- Disassembly already confirms: VW tester addresses F1A0/F1A1/F1A4/F198/F199,
  "TP2.0"/"KWP2000"/"KWP1281" strings, and `com/voltasit/obdeleven/utils/bluetooth/`
  (BluetoothConnectionHelper / BluetoothScanHelper / LeBluetoothDevice; GATT UUIDs
  0000ffe0/ffe1/ffe3/ffe4 + CCCD 2902) — i.e. the SPP/Gen1 dialect from §3 is fully
  statically readable, and the same recipe applies to the Gen1-era 0.34.1/0.37.1 APKs.
