"""Component signature metadata: function names, CV names, parameter
specs (the arg_info zctrl type masks) and the parameter list — the
parse-result metadata the pipeline assembles component headers from."""

from __future__ import annotations

import re

from ..container import u32


# ---- zend type masks (Zend/zend_type_info.h; IS_STRING = 6 -> 1<<6 = 0x40) ----
_MAY_BE = [
    (0x2, "null"), (0x4, "false"), (0x8, "true"), (0x10, "int"), (0x20, "float"),
    (0x40, "string"), (0x80, "array"), (0x100, "object"), (0x200, "resource"),
    (0x1000, "callable"), (0x2000, "iterable"), (0x4000, "void"), (0x8000, "static"),
    (0x10000, "mixed"), (0x20000, "never"),
]
_MAY_BE_ANY = 0x3FE  # null|false|true|int|float|string|array|object|resource


def render_type(ctrl: int, classnames: list[str] | None = None) -> str:
    """zend type mask -> a PHP type string ('' = no hint).

    Unknown bit combinations render as the union in canonical order — the
    source's own union order is not recoverable from the mask."""
    mask = ctrl & 0x3FFFF
    names = classnames or []
    if mask == 0:
        return ""
    if mask == _MAY_BE_ANY:
        return "mixed"
    bits = [nm for bit, nm in _MAY_BE if mask & bit]
    if mask & 0x100:
        if names:
            bits = [nm for nm in bits if nm != "object"] + names
        # else keep the plain 'object'
    if not bits:
        return ""
    if len(bits) == 1:
        return bits[0]
    if set(bits) == {"false", "true"}:
        return "bool"
    if bits[0] == "null" and len(bits) == 2:
        return "?" + bits[1]
    return "|".join(bits)


# ---- parse-result component metadata ----


def fn_name_of(r: dict) -> str | None:
    if r["fnrec"] is None:
        return None
    ln = u32(r["fnrec"], 12)
    if 0 < ln and ln + 2 <= len(r["pool"]):
        return r["pool"][2 : 2 + ln].decode("latin-1")
    return None


def max_cv(r: dict) -> int:
    mx = -1
    for n in r["nodes"]:
        for wname in ("op1", "op2", "res"):
            e = n["ent"].get(wname)
            if e and e[0] == 8:
                mx = max(mx, e[1])
    return mx


def pool_names(r: dict) -> list[str]:
    pool = r["pool"]
    namesEnd = len(pool)
    for z in r["zvals"]:
        if "off" in z and (z["off"] & 0xFFFFFFFF) < 0x10000000 and z["off"] >= 2 \
                and z["off"] < namesEnd and (z.get("len", 0) > 0 or "len" not in z):
            namesEnd = min(namesEnd, z["off"])
    strs = []
    o = 2
    while o < namesEnd:
        e = pool.find(b"\0", o)
        if e == -1 or e >= namesEnd:
            e = namesEnd
        strs.append(pool[o:e].decode("latin-1"))
        o = e + 1
    return strs


def arg_specs(r: dict) -> tuple[list[tuple[str, str]], str | None]:
    """[(param name, rendered type), ...] and the rendered return type.

    The pre-node records carry (offset,len) name pairs plus the zend type
    mask (zctrl); the fn&0x2000 slot is the name-less return-type record
    (validated on all 6 ground-truth typed components: hello, hi, join2,
    Dog::__construct, Dog::label, Animal::label)."""
    fn = r["fn"]
    ret = None
    params: list[tuple[str, str]] = []
    pool = r["pool"]
    for idx, p in enumerate(r["pre"]):
        ctrl = p["ctrl"]
        names: list[str] = []
        if p.get("zrec"):
            off, ln = p["zrec"]
            if 0 < ln < 128 and off + ln <= len(pool):
                names.append(pool[off : off + ln].decode("latin-1"))
        for nmrec in p.get("names") or []:
            if nmrec and 0 < nmrec[1] < 128 and nmrec[0] + nmrec[1] <= len(pool):
                names.append(pool[nmrec[0] : nmrec[0] + nmrec[1]].decode("latin-1"))
        ty = render_type(ctrl, names)
        if p["a"] is None:
            if fn & 0x2000 and idx == 0 and ret is None:
                ret = ty
            continue
        off, ln = p["a"]
        nm = pool[off : off + ln].decode("latin-1") if 0 < ln < 64 and off + ln <= len(pool) else None
        params.append((nm, ty))
    return params, ret


def arg_names(r: dict) -> list[str]:
    out = []
    pool = r["pool"]
    for p in r["pre"]:
        if p["a"] is None:
            continue
        off, ln = p["a"]
        if 0 < ln < 64 and off >= 2 and off + ln <= len(pool):
            out.append(pool[off : off + ln].decode("latin-1"))
    return out


def cv_names(r: dict, mode: str, rec_strings: list[str]) -> dict[int, str]:
    names: dict[int, str] = {}
    numCV = max_cv(r) + 1
    if mode == "eval":
        entries = pool_names(r)
        numArgs = u32(r["hdr"], 0x14)
        base = 1 + numArgs if r["fnrec"] is not None else 0
        for k in range(numCV):
            if base + k < len(entries) and re.match(
                    r"^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$", entries[base + k]):
                names[k] = entries[base + k]
    if not names and rec_strings:
        cand = list(rec_strings)
        cand.pop()  # last = fn name
        cand = [s for s in cand if not (s[:1].isupper() and s.lower() != s)]
        for k in range(min(numCV, len(cand))):
            if re.match(r"^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$", cand[k]):
                names[k] = cand[k]
    return names



def param_list(ctx) -> list[str]:
    """Parameter list from the leading RECV nodes + the pre-record arg specs
    (names AND types — benchmark gap #2)."""
    specs, _ = arg_specs(ctx.r)
    params = []
    arg_names_list = [nm for nm, _ in specs]
    arg_types = [ty for _, ty in specs]
    for i in range(ctx.thr):
        op = ctx.op[i]
        if op in (63, 64, 164):
            n = ctx.nodes[i]
            e = n.ent.get("res")
            idx = e.raw if e and e.kind == 8 else len(params)
            k = len(params)
            nm = (arg_names_list[k] if k < len(arg_names_list) and arg_names_list[k]
                  else ctx.cv.get(idx, f"arg{idx}"))
            ty = arg_types[k] if k < len(arg_types) else ""
            if op == 64:
                e2 = n.ent.get("op2")
                if e2 and e2.kind == 1 and e2.raw < len(ctx.zvals):
                    from .operand import zval_php
                    nm += " = " + zval_php(ctx.zvals[e2.raw], e2.raw)
            prefix = "..." if op == 164 else ""
            params.append(("" if not ty else ty + " ") + prefix + "$" + nm)
        elif op is not None and op not in (0, 124, 101):
            break  # first real statement ends the params
    return params


__all__ = ["arg_names", "arg_specs", "cv_names", "fn_name_of", "max_cv",
           "param_list", "pool_names", "render_type"]
