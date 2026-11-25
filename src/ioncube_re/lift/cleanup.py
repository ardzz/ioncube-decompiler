"""Final-emission cleanup for dead decoder temporaries.

A temp whose only occurrence is its own `$Vn = ...;` / `$Tn = ...;`
assignment is dead.  Drop those statements when the right-hand side is a
pure expression (no call whose result could carry side effects, no new).
This catches the condition-chain temps whose expression the structurer
already folded into the consuming if/switch, and array/read temps that the
loop/collector inlined.
"""

from __future__ import annotations

import re

_ASSIGN = re.compile(r"^(\s*)(\$[TV]\d+)\s*=\s*(.*);\s*$")
_VAR = re.compile(r"\$[TV]\d+\b")
_CALL = re.compile(r"([A-Za-z_\\][A-Za-z0-9_\\]*)\s*\(")

# calls with no observable side effect in this context
_SAFE_CALLS = frozenset(
    {
        "isset",
        "empty",
        "_",
        "array_key_exists",
        "array_flip",
        "array_keys",
        "array_merge",
        "array_values",
        "basename",
        "boolval",
        "count",
        "dirname",
        "explode",
        "file_exists",
        "floatval",
        "implode",
        "in_array",
        "intval",
        "is_array",
        "is_bool",
        "is_float",
        "is_int",
        "is_null",
        "is_numeric",
        "is_object",
        "is_string",
        "json_decode",
        "long2ip",
        "preg_match",
        "preg_replace",
        "sprintf",
        "strlen",
        "strtolower",
        "strtoupper",
        "strval",
        "substr",
        "time",
        "trim",
        "urldecode",
        "urlencode",
    }
)


def _pure_rhs(rhs: str) -> bool:
    if "new " in rhs:
        return False
    for m in _CALL.finditer(rhs):
        if m.group(1).lstrip("\\") not in _SAFE_CALLS:
            return False
    return True


def drop_dead_pure_temps(text: str) -> str:
    lines = text.splitlines(keepends=True)
    counts: dict[str, int] = {}
    for line in lines:
        for m in _VAR.finditer(line):
            v = m.group(0)
            counts[v] = counts.get(v, 0) + 1
    out: list[str] = []
    for line in lines:
        m = _ASSIGN.match(line.rstrip("\r\n"))
        if m:
            var, rhs = m.group(2), m.group(3)
            if counts.get(var, 0) == 1 and _pure_rhs(rhs):
                continue
        out.append(line)
    return "".join(out)


__all__ = ["drop_dead_pure_temps"]
