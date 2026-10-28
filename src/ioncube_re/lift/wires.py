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


def _magic(b: bytes) -> bool:
    """The wire header's first word is [type|flags]; its low byte is the 0x02
    component marker, the upper bytes carry per-function flag bits (00 00 00,
    00 00 01, 00 01 00 and 10 00 00 all occur across these samples) — only the
    low byte is invariant, so keying on the full `02 00 00 00` drops whole
    functions."""
    return len(b) >= 4 and (u32(b, 0) & 0xFF) == 0x02 and u32(b, 0) < 0x10000000


def _plausible(b: bytes) -> bool:
    n = len(b)
    if n < 0x90:
        return False
    if not _magic(b):
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
    """All sub-function wires in stream[start..): (offset, size, parse result).

    Returns the WIRE size (r["end"]), not the record size. A record whose
    declared size (the u32 before the wire) is larger than the wire carries a
    trailing region of nested records (nested closure wires + their
    descriptors): those nested wires are found by the outer byte scan and
    their descriptors live between the outer wire's end and the nested
    record, so the wire end — not the declared size — is what keeps the
    per-record descriptor ranges contiguous. Note the descriptor's stored
    size word is the DECLARED size; seed lookup must read it from the
    stream (`u32(stream, off - 4)`), not reuse this wire size."""
    found = []
    n = len(stream)
    p = start
    while p + 0x90 <= n:
        if not _magic(stream[p : p + 4]):
            p += 1
            continue
        decl = None
        if p >= 4:
            s = u32(stream, p - 4)
            if 0x90 <= s and p + s <= n:
                decl = s
        cands = [decl, n - p] if decl is not None else [n - p]
        for S in dict.fromkeys(cands):
            w = stream[p : p + S]
            if not _plausible(w):
                continue
            try:
                r = parse_wire(w)
            except Exception:
                continue
            if not (r["chk"] and r["thr"] > 0):
                continue
            # exact match, or the declared record size with the wire ending
            # early (trailing nested-record region) — the latter is only
            # trusted for the declared size, never the to-EOF fallback
            if r["end"] == S or (decl is not None and S == decl and r["end"] <= S):
                found.append((p, r["end"], r))
                break
        p += 1
    return found


def record_seeds(
    stream: bytes, start: int, end: int, wire_size: int
) -> tuple[int, int] | None:
    """A sub-wire record's (seedA, seedB): the u32 wire-size word followed by 8
    seed bytes.

    A region can contain a coincidental u32 == wire_size (junk, inlined
    literals, earlier wire tails), so the first match is not necessarily the
    record. The real record carries the eval-record marker 0x01 at +0x15
    (byte-verified on healthy records);
    prefer the closest match that has it, else fall back to the closest."""
    best: tuple[int, int, int] | None = None  # (priority, -distance, i)
    i = start
    while i + 12 <= end:
        if u32(stream, i) == wire_size:
            marker = stream[i + 0x15] if i + 0x15 < len(stream) else 0
            pri = 0 if marker == 1 else 1
            cand = (pri, -(i - start), i)
            if best is None or cand < best:
                best = cand
        i += 1
    if best is None:
        return None
    i = best[2]
    return (u32(stream, i + 4), u32(stream, i + 8))


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
        if (
            ln > 4
            and s[i + 2 : i + 4] == b"\x00\x20"
            and i + 4 + ln <= end
            and s[i + 4 : i + 7] == b"/**"
        ):
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


__all__ = [
    "classrec_strings",
    "desc_strings",
    "pool_strings",
    "record_seeds",
    "scan_wires",
    "tail_doccomment",
]


def class_name_hint(
    stream: bytes, start: int, leaf: str, limit: int | None = None
) -> str | None:
    """Recover the declared class name from the tail descriptor records.

    The encoder writes a record per declared symbol; the class record is a
    namespaced identifier whose final segment is the source file's basename.
    Records carry a byte length and a ``00 20`` tag; anonymous-class records
    append ``@anonymous\\0<path>`` and are skipped. Used only when the fixed
    window/pool recovery found no valid class name.
    """
    b = stream
    e = len(b) if limit is None else min(limit, len(b))
    i = start
    while i + 4 <= e:
        ln = int.from_bytes(b[i : i + 2], "little")
        if 0 < ln < 256 and b[i + 2 : i + 4] == b"\x00\x20" and i + 4 + ln <= e:
            payload = b[i + 4 : i + 4 + ln].split(b"\x00", 1)[0].decode("latin-1")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\]*", payload) and "\\" in payload:
                if payload.rsplit("\\", 1)[-1].lower() == leaf.lower():
                    return payload
            i += 4 + ln
            continue
        i += 1
    return None


def class_like_names(stream: bytes, start: int, limit: int | None = None) -> list[str]:
    """Ordered namespaced-identifier records in the tail descriptor region.

    Includes class declarations and namespaced type references; used to name
    the extra class groups of a multi-class component stream.
    """
    b = stream
    e = len(b) if limit is None else min(limit, len(b))
    out: list[str] = []
    i = start
    while i + 4 <= e:
        ln = int.from_bytes(b[i : i + 2], "little")
        if 0 < ln < 256 and b[i + 2 : i + 4] == b"\x00\x20" and i + 4 + ln <= e:
            payload = b[i + 4 : i + 4 + ln].split(b"\x00", 1)[0].decode("latin-1")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\@]*", payload) and "\\" in payload:
                out.append(payload)
            i += 4 + ln
            continue
        i += 1
    return out
