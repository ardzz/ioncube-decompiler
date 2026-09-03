"""Wire discovery: finding the sub-function wires in a decoded component
stream (the validated trailing-region scan) and the names/strings the
stream embeds (the var-embedded name records, the class records, the tail
docblocks, the pool strings)."""

from __future__ import annotations

import re

from ..container import u32
from ..wire import parse_wire


# ---- sub-function wire discovery (the validated trailing-region scan) ----


def _chk_ok(b: bytes) -> bool:
    s1 = 0
    s2 = 0
    for c in b[:0x7C]:
        s1 = (s1 + c) & 0xFF
        s2 = (s2 + s1) & 0xFF
    from ..container import u16

    return u16(b, 0x7C) == ((s1 | (s2 << 8)) & 0xFFFF)


def _plausible(b: bytes) -> bool:
    n = len(b)
    if n < 0x90:
        return False
    if b[:4] != b"\x02\x00\x00\x00":
        return False
    if not _chk_ok(b):
        return False
    thr = u32(b, 0x30)
    if not (1 <= thr <= 100000):
        return False
    for o in (0x28, 0x4C, 0x50, 0x6C, 0x70):
        if u32(b, o) > 1000000:
            return False
    if u32(b, 0x6C) * 24 > n:
        return False
    return True


def scan_wires(stream: bytes, start: int) -> list[tuple[int, int, dict]]:
    """All sub-function wires in stream[start..): (offset, size, parse result)."""
    found = []
    n = len(stream)
    p = start
    while p + 0x90 <= n:
        if stream[p : p + 4] != b"\x02\x00\x00\x00":
            p += 1
            continue
        cands = []
        if p >= 4:
            s = u32(stream, p - 4)
            if 0x90 <= s and p + s <= n:
                cands.append(s)
        cands.append(n - p)
        for S in dict.fromkeys(cands):
            w = stream[p : p + S]
            if not _plausible(w):
                continue
            try:
                r = parse_wire(w)
            except Exception:
                continue
            if r["chk"] and r["end"] == S and r["thr"] > 0:
                found.append((p, S, r))
                break
        p += 1
    return found


def record_seeds(stream: bytes, start: int, end: int, wire_size: int) -> tuple[int, int] | None:
    """A sub-wire record's (seedA, seedB): the u32 wire-size word followed by 8
    seed bytes (M6-KEYTAB)."""
    i = start
    while i + 12 <= end:
        if u32(stream, i) == wire_size:
            return (u32(stream, i + 4), u32(stream, i + 8))
        i += 1
    return None


# ---- stream/wire string extraction ----


def desc_strings(s: bytes, start: int, end: int) -> list[str]:
    """The var-embedded name strings: N x [u16 len LE][00 20][str]."""
    names = []
    i = start
    while i + 4 <= end:
        ln = int.from_bytes(s[i : i + 2], "little")
        if 0 < ln < 64 and s[i + 2 : i + 4] == b"\x00\x20" and i + 4 + ln <= end:
            st = s[i + 4 : i + 4 + ln]
            if re.match(rb"^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$", st):
                names.append(st.decode("latin-1"))
                i += 3 + ln + ((ln + 1) % 2)
                continue
        i += 1
    return names


def classrec_strings(s: bytes, start: int, end: int) -> list[str]:
    names = []
    i = start
    while i + 4 <= end and len(names) < 2:
        ln = int.from_bytes(s[i : i + 2], "little")
        if 0 < ln < 128 and s[i + 2 : i + 4] == b"\x00\x20" and i + 4 + ln <= end:
            st = s[i + 4 : i + 4 + ln]
            if re.match(rb"^[A-Za-z_\x80-\xff][A-Za-z0-9_\\\x80-\xff]*$", st):
                names.append(st.decode("latin-1"))
                i += 3 + ln + ((ln + 1) % 2)
                continue
        i += 1
    return names


def tail_doccomment(s: bytes, start: int, limit: int | None = None) -> str | None:
    end = len(s) if limit is None else limit
    i = start
    while i + 4 <= end:
        ln = int.from_bytes(s[i : i + 2], "little")
        if ln > 4 and s[i + 2 : i + 4] == b"\x00\x20" and i + 4 + ln <= end and s[i + 4 : i + 7] == b"/**":
            return s[i + 4 : i + 4 + ln].decode("latin-1").rstrip()
        i += 1
    return None


def pool_strings(pool: bytes) -> list[bytes]:
    strs = []
    o = 2  # skip the "c0 de" magic
    while o < len(pool):
        e = pool.find(b"\0", o)
        if e == -1:
            e = len(pool)
        strs.append(pool[o:e])
        o = e + 1 + ((len(strs[-1]) + 1) % 2)  # even-byte padding
    return strs


__all__ = ["classrec_strings", "desc_strings", "pool_strings",
           "record_seeds", "scan_wires", "tail_doccomment"]
