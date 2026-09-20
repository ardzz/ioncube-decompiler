"""Eval-mode class-table recovery: the enum cases, the property table
(visibility/type/default), and the class constants embedded in the
descriptor region between the main wire and the first sub-wire (gdiverse4;
byte-verified against the plaintext preview — the default-table values are
the same payload format the sub-wire records use: 'n' null, 's<len>''
string, 'd' float, 'i' int, 'U' no-default; property visibility byte
1=public/2=protected/4=private with 0x80|0x20|0x01 adding
readonly|promoted; the type-mask u32 is the zend MAY_BE set — 0x12=?int,
0x42=?string, 0x20=float, bit 0x01000000 = class-ref with the class name
following as a [u24][name] record)."""

from __future__ import annotations

import re


def _scalar_value(pay: bytes):
    pay = pay.lstrip(b" ")
    if pay[:1] == b"n":
        return None
    if pay[:1] == b"U":
        return "__nodefault__"
    m = re.match(rb"s(\d+)'", pay)
    if m:
        return pay[m.end() : m.end() + int(m.group(1))].decode("latin-1")
    m = re.match(rb"d([\d.eE+-]+)", pay)
    if m:
        return float(m.group(1))
    m = re.match(rb"i(-?\d+)", pay)
    if m:
        return int(m.group(1))
    return None


def enum_cases(s: bytes, start: int, end: int) -> list[tuple[str, str | int | None]]:
    """The enum-case records: [u24 namelen] '`' <name> <check> 00 00 @777...
    with the value payload (s'<len>'') inside the following ~260 metadata
    bytes. Only string/int-backing shapes are recognized; unit-enum cases
    (no value payload) come back with value None."""
    out: list[tuple[str, str | int | None]] = []
    pat = re.compile(rb"\x00\x00\x60(.+?)\x00\x00 @", re.S)
    for m in pat.finditer(s, start, end):
        raw = m.group(1)
        if not raw or len(raw) < 2:
            continue
        name = raw[:-1].decode("latin-1")  # trailing checksum byte
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            continue
        seg = s[m.end() : m.end() + 260]
        v = None
        mv = re.search(rb"s1'(.)", seg)
        if mv:
            v = mv.group(1).decode("latin-1")
        else:
            mv = re.search(rb"s(\d+)'", seg)
            if mv:
                n = int(mv.group(1))
                v = seg[mv.end() : mv.end() + n].decode("latin-1")
            else:
                mv = re.search(rb"i(-?\d+);", seg)
                if mv:
                    v = int(mv.group(1))
        out.append((name, v))
    return out


def class_tail(
    s: bytes, start: int, end: int
) -> dict[str, list[dict | tuple[str, object]]] | None:
    """The property/constant table after the last sub-wire: [u32 count]
    default-value payloads, a 4-byte pad, [u32 count] property records
    ([u24 namelen] ' name' + 12 flag bytes + type-mask u32 [+ class-name
    record]), then [u32 count] constant records ([u24 namelen] '`' name +
    [u24 vlen] value payload). Returns {props, consts} or None if the
    anchors don't parse."""
    n = len(s)
    if start + 12 > n or end > n:
        return None
    i = start
    cnt = int.from_bytes(s[i : i + 4], "little")
    i += 4
    if not (0 < cnt <= 64):
        return None
    defaults = []
    for _ in range(cnt):
        if i + 3 > n:
            return None
        ln = int.from_bytes(s[i : i + 3], "little")
        i += 3
        if i + ln + 1 > n:
            return None
        defaults.append(_scalar_value(s[i : i + ln + 1]))
        i += ln + 1
    if defaults.count("__nodefault__") == cnt and cnt > 2:
        return None  # all-unset defaults: not a property table
    if i + 8 > n:
        return None
    i += 4  # the 00000000 pad
    pcnt = int.from_bytes(s[i : i + 4], "little")
    i += 4
    if not (0 < pcnt <= 64):
        return None
    props = []
    for k in range(pcnt):
        if i + 3 > n:
            return None
        ln = int.from_bytes(s[i : i + 3], "little")
        i += 3
        if i + ln + 1 > n:
            return None
        name = s[i + 1 : i + 1 + ln].decode("latin-1")
        i += ln + 1
        if i + 16 > n:
            return None
        vis = s[i]
        i += 12
        mask = int.from_bytes(s[i : i + 4], "little")
        i += 4
        classname = None
        if mask & 0x01000000:
            if i + 3 > n:
                return None
            ln2 = int.from_bytes(s[i : i + 3], "little")
            i += 3
            if i + ln2 + 1 > n:
                return None
            classname = s[i + 1 : i + 1 + ln2].decode("latin-1")
            i += ln2 + 1
        props.append(
            {
                "name": name,
                "vis": vis,
                "mask": mask,
                "class": classname,
                "default": defaults[k] if k < len(defaults) else "__nodefault__",
            }
        )
    consts = []
    if i + 4 <= n:
        ccnt = int.from_bytes(s[i : i + 4], "little")
        j = i + 4
        if 0 < ccnt <= 64:
            ok = True
            cl = []
            for _ in range(ccnt):
                if j + 3 > n:
                    ok = False
                    break
                ln = int.from_bytes(s[j : j + 3], "little")
                j += 3
                if j + ln + 1 > n or s[j] != 0x60:
                    ok = False
                    break
                nm = s[j + 1 : j + 1 + ln].decode("latin-1")
                j += ln + 1
                if j + 3 > n:
                    ok = False
                    break
                vln = int.from_bytes(s[j : j + 3], "little")
                j += 3
                if j + vln + 1 > n:
                    ok = False
                    break
                cl.append((nm, _scalar_value(s[j : j + vln + 1])))
                j += vln + 1
            if ok and all(re.match(r"^[A-Z_][A-Z0-9_]*$", nm) for nm, _ in cl):
                consts = cl
    return {"props": props, "consts": consts}


def prop_type(mask: int, classname: str | None) -> str:
    """A zend MAY_BE mask as a PHP type string ('' = untyped)."""
    if classname:
        return classname
    NULL = 0x2
    FALSE = 0x4
    TRUE = 0x8
    LONG = 0x10
    DOUBLE = 0x20
    STRING = 0x40
    if mask == 0:
        return ""
    parts = []
    nullable = bool(mask & NULL)
    base = mask & ~(NULL | FALSE | TRUE)
    if base == LONG:
        parts.append("int")
    elif base == DOUBLE:
        parts.append("float")
    elif base == STRING:
        parts.append("string")
    elif base == (LONG | DOUBLE):
        parts.append("int")
        parts.append("float")
    elif base == (FALSE | TRUE):
        parts.append("bool")
    if not parts:
        return ""
    t = "?".strip()
    t = ("?" if nullable else "") + ("|".join(parts))
    return t


def prop_declare(p: dict) -> str:
    vis = {1: "public", 2: "protected", 4: "private"}.get(p["vis"] & 0x7, "public")
    ro = " readonly" if p["vis"] & 0x20 else ""
    t = prop_type(p["mask"], p["class"])
    t = (t + " ") if t else ""
    d = p["default"]
    if d == "__nodefault__":
        dv = ""
    elif d is None:
        dv = " = null"
    elif isinstance(d, bool):
        dv = " = true" if d else " = false"
    elif isinstance(d, str):
        dv = " = '" + d.replace("\\", "\\\\").replace("'", "\\'") + "'"
    elif isinstance(d, float):
        dv = " = " + repr(d)
    else:
        dv = f" = {d}"
    return f"    {vis}{ro} {t}${p['name']}{dv};"


def promoted_param(p: dict) -> str:
    """A promoted constructor parameter from a promoted property record
    (vis bit 0x80): 'public readonly Suit' — the declaration prefix, no
    name/default (those come from the RECV/param record)."""
    vis = {1: "public", 2: "protected", 4: "private"}.get(p["vis"] & 0x7, "public")
    ro = " readonly" if p["vis"] & 0x20 else ""
    t = prop_type(p["mask"], p["class"])
    t = (t + " ") if t else ""
    return f"{vis}{ro} {t}".rstrip()


__all__ = ["class_tail", "enum_cases", "promoted_param", "prop_declare", "prop_type"]
