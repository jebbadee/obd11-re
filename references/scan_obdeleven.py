#!/usr/bin/env python3
"""scan_obdeleven.py — scan OBDeleven obfuscated DEX with decoded region map.

Vendor DEX quirks — verified facts (obdeleven 0.34.1/0.36.0/0.37.1/0.107.1,
2026-11-25/26; scripted dword reads + baksmali 2.5.2 disassembly of ORIGINALS):
  * classes*.dex BODY (string data, type ids, method ids, class defs) is BYTE-INTACT
    and baksmali 2.5.2 disassembles the ORIGINAL apk files CLEANLY (readable smali,
    class names, sources, method bodies) — no descrambling step is required for
    static RE; see README-apks-here.md for the exact command.
  * Header field ORDER and VALUES are standard DEX (magic "dex\\n035/038" verified on
    every copy; file_size/header_size/region size+offsets all correct; checksum slot
    present). Oddities: link_size slot = 0x12345678, map_off slot = 0, endian_tag slot
    holds a value pointing at n-224 (the scrambled tail region). baksmali 2.5.2 accepts
    this; my rebuild_dex.py output was REJECTED by baksmali ("Invalid endian tag"), so
    treat the rebuild as experimental and prefer disassembling originals.
  * Region map survives in the LAST ~224 bytes: a 4-dword vendor lead-in, then
    12-byte (type, size, off) triples in ascending-type order ending with the MAP
    self-descriptor (type 0x1000 whose off points back to the triple block start);
    triple OFFSETS are true file offsets (string_ids off=0x70=112 on every version),
    SIZE semantics = vendor-side unit counts.

Usage:
  scan_obdeleven.py APK [token ...]      # print decoded map, scan raw dex for tokens
"""
import zipfile, struct, sys, re

VENDOR_TYPES = {0: "header", 1: "string_ids", 2: "type_ids", 3: "proto_ids", 4: "field_ids", 5: "method_ids",
                6: "class_defs?", 0x2001: "anno_dir?", 0x2003: "anno_set?", 0x1001: "anno?",
                0x2002: "anno_type?", 0x2004: "class_data?", 0x2000: "anno?", 0x2005: "code?",
                0x1003: "static_values?", 0x1002: "??", 0x2006: "??", 0x1000: "MAP(self-desc)"}

def decode_map(dex):
    """Find trailing (type,size,off) triples by anchoring on the MAP self-descriptor
    (type dword 0x1000) near EOF, then walking backward."""
    n = len(dex)
    anchor = None
    for p in range(n - 260, n - 11, 4):
        if struct.unpack_from("<I", dex, p)[0] == 0x1000:
            # its two companions: size, off sane
            sz, off = struct.unpack_from("<2I", dex, p + 4)
            if sz <= 40 and off <= n:
                anchor = p
    if anchor is None:
        return n, None, []
    # walk backward in 12B steps while triples look sane
    start = anchor
    prev_type = None
    while start - 12 >= n - 4096:
        t, sz, off = struct.unpack_from("<3I", dex, start - 12)
        if t not in VENDOR_TYPES or sz > n or off > n:
            break
        start -= 12
        if t == 0 and prev_type == 1:   # reached the header triple just above string_ids: stop
            break
        prev_type = t
    triples = []
    p = start
    while p + 12 <= anchor + 12:
        t, sz, off = struct.unpack_from("<3I", dex, p)
        if t not in VENDOR_TYPES:
            break
        triples.append((t, sz, off))
        p += 12
    lead = struct.unpack_from("<4I", dex, max(0, start - 16)) if start >= 16 else None
    return n, (start, lead), triples

def main():
    apk = sys.argv[1]
    tokens = [t for t in sys.argv[2:] if not t.startswith("--")]
    z = zipfile.ZipFile(apk)
    for dn in sorted(x for x in z.namelist() if x.endswith(".dex")):
        dex = z.read(dn)
        n, meta, triples = decode_map(dex)
        if meta is None:
            print("== %s [%s] size=%d  (no decodable map tail — raw scan only)" % (apk, dn, n))
        else:
            start, lead = meta
            print("== %s [%s] size=%d  map@%s lead-in=%s" % (apk, dn, n, hex(start), [hex(x) for x in (lead or [])]))
        print("   decoded region map (%d triples):" % len(triples))
        cov = sorted(triples, key=lambda x: x[2])
        for t, sz, off in cov:
            print("      %-14s size=%-9d off=%-10s end=%s" % (VENDOR_TYPES[t], sz, hex(off), hex(off + sz)))
        # contiguity report
        gaps = 0; prev_end = 112
        for t, sz, off in cov:
            if t == 0x1000: continue
            gaps += max(0, off - prev_end); prev_end = max(prev_end, off + sz)
        print("   total uncovered gap between regions:", gaps, "bytes")
        for tok in tokens:
            pat = re.compile(re.escape(tok).encode(), re.IGNORECASE)
            hits = list(re.finditer(pat, dex))
            print("   token %r: %d hits" % (tok, len(hits)))
            for m in hits[:5]:
                s = max(0, m.start() - 40)
                ctx = re.sub(rb"[^\x20-\x7e]", b".", dex[s:m.start() + len(m.group(0)) + 180])
                print("      @%s: %s" % (hex(m.start()), ctx.decode(errors="replace")[:210]))

if __name__ == "__main__":
    main()
