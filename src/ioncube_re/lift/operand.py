"""Operand rendering: wire operands -> PHP source text.

Pure value helpers (literals, zvals, quoting) live at module level; the context-bound read side (temps/CVs/refs, the single-use temp
inlining decision) is the OperandRenderer — one interface, the LSP role
the task's architecture spells. It never writes statements and never
mutates accounting: rendering only reads the context.

The CV-slot +5 rule lives HERE, in ``ex``: a temp/VAR operand renders as
$T/$V with the slot number minus 5 — the x86_64 ABI (execute_data's 5
fixed slots precede the CVs; loader-verified, M6-OPERANDS §1.3 — the
dawwinci 3-slot fallback is a different, 32-bit ABI, DAWWINCI-DIFF §4.3).
"""

from __future__ import annotations

import re

from ..interned import CONSTANT_TOKENS, interned_name, render_placeholder
from ..serarr import decode_serarr, php_array_literal

from .model import LiftContext, Node

def php_quote(s: bytes) -> str:
    t = s.decode("latin-1")
    if any(c in t for c in "\n\r\t"):
        t = t.replace("\\", "\\\\").replace('"', '\\"')
        t = t.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return f'"{t}"'
    return "'" + t.replace("\\", "\\\\").replace("'", "\\'") + "'"


def zval_php(z: dict, idx: int) -> str:
    """A zval as a PHP expression (icl_zval_php port + interned resolution)."""
    t = z["type"] & 0xFF
    if t == 4:
        return str(z["a"])  # int (u32 view — matches the PHP oracle print)
    if t == 1:
        return "null"
    if t == 2:
        return "false"  # zend IS_FALSE
    if t == 3:
        return "true"  # zend IS_TRUE
    if t == 0x12:
        return "true" if z["a"] else "false"
    if t in (6, 0xB):
        if "str" in z:
            return php_quote(z["str"])
        if "off" in z:
            signed = z["off"] - 0x100000000 if z["off"] > 0x7FFFFFFF else z["off"]
            if signed < 0:
                name = interned_name(-signed, z.get("len", 0))
                if name:
                    # compile-time constant tokens render bare; every other
                    # resolved interned name is the string value it names
                    return name if name in CONSTANT_TOKENS else php_quote(name.encode())
                return render_placeholder(-signed, z.get("len", 0))
        return f"/*str?{idx}*/"
    if t == 7:  # serialized-array zval — the dawwinci grammar (serarr.py)
        if "str" in z:
            pairs = decode_serarr(z["str"])
            if pairs is not None:
                return php_array_literal(pairs)
            # parse failed: fall back to the string-scrape (M6 §7.7)
            items = []
            for m in re.finditer(rb"s(\d+)'", z["str"]):
                ln = int(m.group(1))
                start = m.end() + 2  # skip the opening quote delimiters
                if start < len(z["str"]):
                    items.append(php_quote(z["str"][start : start + ln]))
            return "[%s/* +ser */]" % ", ".join(items) if items else f"[/* serialized array {idx} */]"
        return f"[/* serialized array {idx} */]"
    return f"/*zval{idx} t={t}*/"


def zval_name(z: dict) -> str | None:
    """A zval as a bare name (callee names / FETCH variable names)."""
    t = z["type"] & 0xFF
    if t in (6, 0xB) and "str" in z:
        return z["str"].decode("latin-1")
    if "off" in z and (t in (6, 0xB)):
        signed = z["off"] - 0x100000000 if z["off"] > 0x7FFFFFFF else z["off"]
        if signed < 0:
            return interned_name(-signed, z.get("len", 0))
    return None


def bare(e: str) -> str:
    if len(e) >= 2 and e[0] in "'\"" and e[-1] == e[0]:
        return e[1:-1]
    return e


def unwrap(e: str) -> str:
    """Strip one redundant outer paren layer: "(($a . $b))" -> "($a . $b)"."""
    if len(e) > 1 and e[0] == "(" and e[-1] == ")":
        d = 0
        for k, c in enumerate(e):
            if c == "(":
                d += 1
            elif c == ")":
                d -= 1
                if d == 0 and k < len(e) - 1:
                    return e
        if d == 0:
            return e[1:-1]
    return e


# PHP operators with precedence BELOW '.' (??, ?:, ||, &&, and/or/xor) —
# operands carrying them keep their own parens inside a concat chain
_CONCAT_UNSAFE_RE = re.compile(r"\?\?|\|\||&&|\? | or | and | xor ")


def concat_pair(a: str, b: str) -> str:
    """CONCAT without the defensive outer parens; operands that carry a
    lower-precedence operator than '.' keep their own parens."""
    if a and not a.startswith("(") and _CONCAT_UNSAFE_RE.search(a):
        a = "(" + a + ")"
    if b and not b.startswith("(") and _CONCAT_UNSAFE_RE.search(b):
        b = "(" + b + ")"
    return f"{a} . {b}"


def cast_name(ext: int) -> str:
    m = {1: "is_null", 2: "is_bool", 3: "is_long", 4: "int", 5: "float", 6: "string",
         7: "array", 8: "is_null", 10: "object"}
    return m.get(ext, f"type{ext}")


class OperandRenderer:
    """The read side: operand -> source text, honoring the context's temp
    inlining and CV names. Attached to every LiftContext as ``ctx.render``."""

    def __init__(self, ctx: LiftContext):
        self.ctx = ctx

    def ex(self, n: Node, which: str) -> str | None:
        e = n.ent.get(which)
        if e is None:
            return None
        t, raw = e.kind, e.raw
        conv = getattr(n, which)
        if t == 8:
            return self.ctx.cv_name(raw)
        if t & 6:
            slot = conv // 16
            es = self.ctx.effSlot.get(f"{n.i}:{which}")
            if es is not None:
                slot = es
            if self.ctx.inlinable(slot, n.i):
                return self.ctx.tempExpr[slot]
            # the CV-slot +5 rule (x86_64 ABI, M6-OPERANDS §1.3)
            return ("$V" if t & 4 else "$T") + str(slot - 5)
        if t == 1 and raw < len(self.ctx.zvals):
            return zval_php(self.ctx.zvals[raw], raw)
        if t == 0 and raw == 0xFFFFFFFF:
            return None  # the unused marker: an internal field, never source
        return str(raw)

    def ex_op1(self, n: Node) -> str | None:
        return self.ex(n, "op1")

    def ex_op2(self, n: Node) -> str | None:
        return self.ex(n, "op2")

    def ch(self, e: str | None) -> str:
        return "null" if e is None else e

    def opnd_text(self, n: Node, which: str) -> str | None:
        e = n.ent.get(which)
        if e is None:
            return None
        t, raw = e.kind, e.raw
        if t == 8:
            cv = self.ctx.cv
            return f"CV{raw}" + (f"({cv[raw]})" if raw in cv else "")
        if t & 6:
            return ("V" if t & 4 else "T") + str(getattr(n, which) // 16 - 5)
        if t == 1 and raw < len(self.ctx.zvals):
            z = self.ctx.zvals[raw]
            tt = z["type"] & 0xFF
            if tt == 4:
                return f"int({z['a']})"
            if tt == 1:
                return "null"
            if tt == 7:
                pairs = decode_serarr(z["str"]) if "str" in z else None
                if pairs is not None:
                    return "array(" + php_array_literal(pairs) + ")"
                return "array(" + (z["str"][:40].decode("latin-1") + "..." if "str" in z else "ser") + ")"
            if "str" in z:
                return ("string(" + php_quote(z["str"]) + ")" if tt == 6
                        else "class(" + php_quote(z["str"]) + ")")
            if "off" in z:
                signed = z["off"] - 0x100000000 if z["off"] > 0x7FFFFFFF else z["off"]
                return f"interned-{-signed}(len {z.get('len', 0)})"
            return f"zval{raw}"
        if t == 0 and raw == 0xFFFFFFFF:
            return "unused"
        return str(raw)

    def obj(self, e: str | None) -> str:
        if e in (None, "null", "0"):
            return "$this"
        # the $this receiver arrives as a bare raw value (type-0 operand) —
        # ktab-decoded junk of any magnitude (2250663856, 262, 1): a real
        # receiver renders as a $CV/$T expression, never bare digits
        if e.isdigit():
            return "$this"
        return e

    def callee_name(self, n: Node, which: str) -> str:
        e = n.ent.get(which)
        if e is None:
            return "?"
        if e.kind == 1 and e.raw < len(self.ctx.zvals):
            nm = zval_name(self.ctx.zvals[e.raw])  # pool string OR interned name
            if nm is not None:
                return nm
        return self.ch(self.ex(n, which))


__all__ = [
    "OperandRenderer", "bare", "cast_name", "concat_pair", "php_quote",
    "unwrap", "zval_name", "zval_php",
]
