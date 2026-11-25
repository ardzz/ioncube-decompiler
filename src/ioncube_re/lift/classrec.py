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

from .operand import class_ref


def _next_key_or_close(pay: bytes, i: int) -> int:
    """Skip a value's metadata to the next array key or the closing `}`.

    Metadata is `;`-separated numbers (`262;4294967295;1;22;`); a key is a
    digit run followed by `'` (string key) or `:` (int key), and `}` closes
    the array."""
    n = len(pay)
    while i < n:
        if pay[i : i + 1] == b"}":
            return i
        m = re.match(rb"\d+[':]", pay[i:])
        if m:
            return i
        i += 1
    return n


def _parse_array(pay: bytes, i: int):
    """The ionCube serarr array form: `[` entries `}`.

    Keys: `<len>'<bytes>` (string) or `<len>:<digits>` (int).  Values:
    `s<len>'<bytes>`, a nested `[...]`, `i<n>;`, `f`/`t`/`n`.  Metadata
    follows every value and is skipped.  Returns (pairs, next_index)."""
    i += 1  # [
    items: list[tuple[object, object]] = []
    n = len(pay)
    while i < n and pay[i : i + 1] != b"}":
        # key
        m = re.match(rb"(\d+)'", pay[i:])
        if m:
            ln = int(m.group(1))
            k = i + m.end()
            key = pay[k : k + ln].decode("latin-1")
            i = k + ln
        else:
            m = re.match(rb"(\d+):(\d+)", pay[i:])
            if not m:
                break
            key = int(m.group(2))
            i += m.end()
        # value
        if pay[i : i + 1] == b"[":
            val, i = _parse_array(pay, i)
        elif pay[i : i + 1] == b"s":
            m = re.match(rb"s(\d+)'", pay[i:])
            if not m:
                break
            ln = int(m.group(1))
            j = i + m.end()
            val = pay[j : j + ln].decode("latin-1")
            i = j + ln
        elif pay[i : i + 1] == b"i":
            m = re.match(rb"i(-?\d+)", pay[i:])
            if not m:
                break
            val = int(m.group(1))
            i += m.end()
        elif pay[i : i + 1] == b"d":
            m = re.match(rb"d([\d.eE+-]+)", pay[i:])
            if not m:
                break
            val = float(m.group(1))
            i += m.end()
        elif pay[i : i + 1] == b"f":
            val, i = False, i + 1
        elif pay[i : i + 1] == b"t":
            val, i = True, i + 1
        elif pay[i : i + 1] == b"n":
            val, i = None, i + 1
        else:
            break
        items.append((key, val))
        i = _next_key_or_close(pay, i)
    if i < n and pay[i : i + 1] == b"}":
        i += 1
    return items, i


def _scalar_value(pay: bytes):
    pay = pay.lstrip(b" ")
    # the 00443+ default payloads carry a 0x81 type tag before the value
    # (`81 [}` empty array, `81 [4'ulaws7'...}` assoc array, `81 f2;0;`
    # false, `81 s4'/tmp` string)
    if pay[:1] == b"\x81":
        pay = pay[1:]
    if pay[:1] == b"n":
        return None
    if pay[:1] == b"U":
        return "__nodefault__"
    if pay[:1] == b"f":
        return False
    if pay[:1] == b"t":
        return True
    if pay.startswith(b"["):
        items, _ = _parse_array(pay, 0)
        return items
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


def php_literal(v) -> str:
    """A PHP source literal for a decoded default value (arrays recurse)."""
    if isinstance(v, list):
        seq = all(isinstance(k, int) and k == idx for idx, (k, _) in enumerate(v))
        parts = []
        for k, val in v:
            s = php_literal(val)
            if not seq:
                ks = str(k) if isinstance(k, int) else "'" + str(k) + "'"
                s = ks + " => " + s
            parts.append(s)
        return "[" + ", ".join(parts) + "]"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"
    return repr(v)


def _default_table(s: bytes, i: int, n: int, cnt: int):
    """Read `cnt` default-value records: [u24 len][0x20][payload].

    Returns (values, next_offset) or None when the records do not fit.
    """
    vals = []
    for _ in range(cnt):
        if i + 3 > n:
            return None
        ln = int.from_bytes(s[i : i + 3], "little")
        i += 3
        if ln > 1 << 20 or i + ln + 1 > n:
            return None
        vals.append(_scalar_value(s[i : i + ln + 1]))
        i += ln + 1
    return vals, i


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
    if not (0 <= cnt <= 64):
        return None
    inst: list = []
    if cnt:
        dt = _default_table(s, i, n, cnt)
        if dt is None:
            return None
        inst, i = dt
    if inst.count("__nodefault__") == cnt and cnt > 2:
        return None  # all-unset defaults: not a property table
    # static properties have their own default table; the next u32 is its
    # count (zero when the class has no static properties — the old reader
    # took this word as a pad)
    if i + 8 > n:
        return None
    scnt = int.from_bytes(s[i : i + 4], "little")
    i += 4
    stat: list = []
    if scnt:
        if not (0 < scnt <= 64):
            return None
        dt = _default_table(s, i, n, scnt)
        if dt is None:
            return None
        stat, i = dt
    pcnt = int.from_bytes(s[i : i + 4], "little")
    i += 4
    if not (0 < pcnt <= 64):
        return None
    props = []
    di = si = 0
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
        if vis & 0x10:  # static: its default comes from the static table
            d = stat[si] if si < len(stat) else "__nodefault__"
            si += 1
        else:
            d = inst[di] if di < len(inst) else "__nodefault__"
            di += 1
        props.append(
            {
                "name": name,
                "vis": vis,
                "mask": mask,
                "class": classname,
                "default": d,
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
    if not consts:
        # 00442 constants: [u24 namelen][0x60][NAME][u24 vlen]
        # [20 81][serialized scalar], each preceded by an 8-byte header;
        # scan the tail for the name/value records instead of the fixed
        # count table layout used by the older generations.
        seen = set()
        for k in range(start, max(start, end - 8)):
            ln = int.from_bytes(s[k : k + 3], "little")
            if not (1 <= ln <= 64) or k + 4 + ln + 3 > end:
                continue
            if s[k + 3] != 0x60:
                continue
            nm = s[k + 4 : k + 4 + ln].decode("latin-1")
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", nm) or nm in seen:
                continue
            j = k + 4 + ln
            vln = int.from_bytes(s[j : j + 3], "little")
            if not (0 < vln <= 256) or j + 3 + vln > end:
                continue
            payload = s[j + 3 : j + 3 + vln]
            mv = re.search(rb"[sdinU]", payload)
            if mv is None:
                continue
            val = _scalar_value(payload[mv.start() :])
            seen.add(nm)
            consts.append((nm, val))
    return {"props": props, "consts": consts}


def doc_prop_table(s: bytes, start: int, end: int) -> list[dict] | None:
    """The 00449 property-table variant: variable-length records carrying a
    doc comment between the flags and the type metadata.

    `[u32 count][count × [u24 len][0x20][payload]][u32 pad][u32 pcnt]`,
    then per property `[u24 namelen][0x20][name][u32 visibility]
    [u24 doclen][0x20][doc][8 bytes type/metadata]`.  The fixed 16-byte
    flag block of the older generations is absent, so ``class_tail``'s
    records land inside the doc text and every later record is misread.
    The doc text is preserved on the returned record (``doc``)."""
    n = len(s)
    if start + 12 > n or end > n:
        return None
    i = start
    cnt = int.from_bytes(s[i : i + 4], "little")
    i += 4
    if not (0 <= cnt <= 64):
        return None
    inst: list = []
    if cnt:
        dt = _default_table(s, i, n, cnt)
        if dt is None:
            return None
        inst, i = dt
    if i + 8 > n:
        return None
    scnt = int.from_bytes(s[i : i + 4], "little")
    i += 4
    stat: list = []
    if scnt:
        if not (0 < scnt <= 64):
            return None
        dt = _default_table(s, i, n, scnt)
        if dt is None:
            return None
        stat, i = dt
    pcnt = int.from_bytes(s[i : i + 4], "little")
    i += 4
    if not (0 < pcnt <= 64):
        return None
    props = []
    di = si = 0
    for k in range(pcnt):
        if i + 4 > n:
            return None
        ln = int.from_bytes(s[i : i + 3], "little")
        i += 3
        if not (1 <= ln <= 64) or s[i] not in (0x20, 0x60) or i + 1 + ln > n:
            return None
        name = s[i + 1 : i + 1 + ln].decode("latin-1")
        if not re.fullmatch(r"[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*", name):
            return None
        i += 1 + ln
        if i + 7 > n:
            return None
        vis = int.from_bytes(s[i : i + 4], "little") & 0xFF
        i += 4
        dlen = int.from_bytes(s[i : i + 3], "little")
        i += 3
        if dlen > 1 << 20 or i + 1 + dlen > n or s[i] != 0x20:
            return None
        doc = s[i + 1 : i + 1 + dlen].decode("latin-1")
        i += 1 + dlen
        if doc and not doc.lstrip().startswith("/*"):
            return None
        if i + 8 > n:
            return None
        i += 8  # type/metadata trailer
        if vis & 0x10:
            d = stat[si] if si < len(stat) else "__nodefault__"
            si += 1
        else:
            d = inst[di] if di < len(inst) else "__nodefault__"
            di += 1
        props.append(
            {
                "name": name,
                "vis": vis,
                "mask": 0,
                "class": None,
                "default": d,
                "doc": doc,
            }
        )
    return props


def scan_prop_table(s: bytes, start: int, end: int) -> list[dict] | None:
    """Locate a property table when the fixed tail anchors don't parse.

    Some generations put extra metadata between the default table and the
    property records, so the fixed-offset reader returns None even though
    the records are present.  Scan for a plausible `[u32 count]` followed
    by exactly count records of
    `[u24 namelen][0x20|0x60][name][16 flag/type bytes]`.
    """
    best: list[dict] = []
    for p in range(start, max(start, end - 8)):
        cnt = int.from_bytes(s[p : p + 4], "little")
        if not (1 <= cnt <= 64):
            continue
        j = p + 4
        props: list[dict] = []
        ok = True
        for _ in range(cnt):
            if j + 4 > end:
                ok = False
                break
            ln = int.from_bytes(s[j : j + 3], "little")
            if not (1 <= ln <= 64) or j + 4 + ln + 16 > end:
                ok = False
                break
            if s[j + 3] not in (0x20, 0x60):
                ok = False
                break
            nm = s[j + 4 : j + 4 + ln].decode("latin-1")
            if not re.fullmatch(r"[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*", nm):
                ok = False
                break
            k = j + 4 + ln
            vis = s[k]
            mask = int.from_bytes(s[k + 12 : k + 16], "little")
            k += 16
            classname = None
            if mask & 0x01000000:
                if k + 4 > end:
                    ok = False
                    break
                ln2 = int.from_bytes(s[k : k + 3], "little")
                if not (1 <= ln2 <= 128) or k + 4 + ln2 > end:
                    ok = False
                    break
                classname = s[k + 4 : k + 4 + ln2].decode("latin-1")
                k += 4 + ln2
            props.append(
                {
                    "name": nm,
                    "vis": vis,
                    "mask": mask,
                    "class": classname,
                    "default": "__nodefault__",
                }
            )
            j = k
        if ok and len(props) == cnt and len(props) > len(best):
            best = props
    return best or None


def prop_type(mask: int, classname: str | None) -> str:
    """A zend MAY_BE mask as a PHP type string ('' = untyped)."""
    if classname:
        return class_ref(classname)
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
    t = "|".join(parts)
    if nullable:
        # only a single type may use the `?T` shorthand — `?int|float` is a
        # parse error, a nullable union is `int|float|null`
        t = (t + "|null") if "|" in t else ("?" + t)
    return t


def _nullable(t: str) -> str:
    """`t` rendered so that it accepts null (used for null-defaulted props)."""
    if not t or t in ("mixed", "null"):
        return t
    if "|" in t:
        parts = [p[1:] if p.startswith("?") else p for p in t.split("|")]
        if "null" not in parts:
            parts.append("null")
        return "|".join(parts)
    return t if t.startswith("?") else "?" + t


def prop_declare(p: dict) -> str:
    vis = {1: "public", 2: "protected", 4: "private"}.get(p["vis"] & 0x7, "public")
    t = prop_type(p["mask"], p["class"])
    d = p["default"]
    if d is None:
        # a typed property with a null default must admit null:
        # `private int $x = null;` is a compile error
        t = _nullable(t)
    # PHP readonly properties are typed and have no default (promoted ones
    # aside). The wire can carry the 0x20 bit with an untyped or null-default
    # property; emitting it there is a fatal, so drop the modifier rather
    # than produce invalid source.
    ro = " readonly" if (p["vis"] & 0x20 and t and d == "__nodefault__") else ""
    st = " static" if (p["vis"] & 0x10 and not ro) else ""
    t = (t + " ") if t else ""
    if d == "__nodefault__":
        dv = ""
    elif d is None:
        dv = " = null"
    else:
        dv = " = " + php_literal(d)
    decl = f"    {vis}{st}{ro} {t}${p['name']}{dv};"
    doc = p.get("doc")
    if doc:
        # the wire records the docblock with a 4-space continuation indent;
        # the class body adds its own 4 spaces, so normalize each line to
        # the reference block shape (`/**` at member indent, ` *` under it)
        lines = [ln.strip() for ln in doc.strip().splitlines()]
        if lines and lines[0].startswith("/*"):
            docTxt = "\n".join(
                ["    " + lines[0]] + ["     " + ln for ln in lines[1:]]
            )
            return docTxt + "\n" + decl
    return decl


def promoted_param(p: dict) -> str:
    """A promoted constructor parameter from a promoted property record
    (vis bit 0x80): 'public readonly Suit' — the declaration prefix, no
    name/default (those come from the RECV/param record)."""
    vis = {1: "public", 2: "protected", 4: "private"}.get(p["vis"] & 0x7, "public")
    ro = " readonly" if p["vis"] & 0x20 else ""
    t = prop_type(p["mask"], p["class"])
    t = (t + " ") if t else ""
    return f"{vis}{ro} {t}".rstrip()


__all__ = [
    "class_tail",
    "doc_prop_table",
    "enum_cases",
    "promoted_param",
    "prop_declare",
    "prop_type",
    "scan_prop_table",
]
