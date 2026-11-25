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
_ASSIGN_HEAD = re.compile(r"^(\s*)(\$[TV]\d+)\s*=\s*(.*)$")
_VAR = re.compile(r"\$[TV]\d+\b")
_CALL = re.compile(r"([A-Za-z_\\][A-Za-z0-9_\\]*)\s*\(")

# calls with no observable side effect in this context
_SAFE_CALLS = frozenset(
    {
        "isset",
        "empty",
        "_",
        "abs",
        "addslashes",
        "array_key_exists",
        "array_flip",
        "array_keys",
        "array_merge",
        "array_values",
        "base64_decode",
        "base64_encode",
        "basename",
        "boolval",
        "ceil",
        "chunk_split",
        "count",
        "dirname",
        "explode",
        "file_exists",
        "floatval",
        "floor",
        "htmlentities",
        "htmlspecialchars",
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
        "json_encode",
        "lcfirst",
        "long2ip",
        "ltrim",
        "max",
        "min",
        "nl2br",
        "number_format",
        "preg_match",
        "preg_replace",
        "preg_split",
        "rawurldecode",
        "rawurlencode",
        "round",
        "rtrim",
        "serialize",
        "sprintf",
        "str_replace",
        "str_split",
        "strlen",
        "strpos",
        "strrev",
        "strrpos",
        "strtolower",
        "strtoupper",
        "strval",
        "substr",
        "substr_count",
        "time",
        "trim",
        "ucfirst",
        "ucwords",
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


def _multiline_dead_temps(lines: list[str]) -> set[int]:
    """Line spans of dead multi-line decoder temporary assignments.

    A heredoc-bearing `$Tn = (... <<<'EOT' ... EOT) ...;` statement spans
    several lines, so the per-line dead-store scan cannot see it.  Drop the
    whole statement when the temp has no other occurrence in code and the
    expression (heredoc body masked out) is side-effect-free.
    """
    state: dict = {}
    code: list[str] = []
    occ: dict[str, int] = {}
    for line in lines:
        raw = line.rstrip("\r\n")
        m = _mask_code(raw, _scan_spans(raw, state))
        code.append(m)
        for x in _VAR.finditer(m):
            occ[x.group(0)] = occ.get(x.group(0), 0) + 1
    drop: set[int] = set()
    idx = 0
    while idx < len(lines):
        m = code[idx]
        am = _ASSIGN_HEAD.match(m)
        tail = m[am.end(2) :] if am is not None else ""
        # a temporary statement that does not terminate on its first code
        # line (the heredoc form; a same-line assignment is handled by the
        # per-line pass)
        if am is not None and ";" not in tail:
            var = am.group(2)
            rest = [tail]
            j = idx + 1
            while j < len(lines) and ";" not in rest[-1]:
                rest.append(code[j])
                j += 1
            complete = bool(rest) and ";" in rest[-1]
            if (
                complete
                and occ.get(var, 0) == 1
                and _pure_rhs(" ".join(rest))
            ):
                drop.update(range(idx, j))
            idx = j
            continue
        idx += 1
    return drop


def drop_dead_pure_temps(text: str) -> str:
    lines = text.splitlines(keepends=True)
    counts: dict[str, int] = {}
    defs: dict[str, list[int]] = {}
    for idx, line in enumerate(lines):
        for m in _VAR.finditer(line):
            v = m.group(0)
            counts[v] = counts.get(v, 0) + 1
        m = _ASSIGN.match(line.rstrip("\r\n"))
        if m:
            defs.setdefault(m.group(2), []).append(idx)
    state: dict = {}
    masks: list[str] = []
    for line in lines:
        raw = line.rstrip("\r\n")
        masks.append(_mask_code(raw, _scan_spans(raw, state)))

    def _repeats_near(idx: int, rhs: str) -> bool:
        """The same code expression is evaluated by a control statement on
        an adjacent line — the value a staging temp was folded into."""
        rmask = _mask_code(rhs, _scan_spans(rhs, {})).strip()
        if not rmask:
            return False
        for k in range(max(0, idx - 2), min(len(masks), idx + 3)):
            if k == idx:
                continue
            if not re.match(
                r"^[\s}]*(?:if|elseif|while|for|switch|return|echo|print)\b",
                masks[k],
            ):
                continue
            if rmask in masks[k]:
                return True
        return False

    drop: set[int] = set()
    rewrite: dict[int, str] = {}
    for var, idxs in defs.items():
        # `$T = $T;` is a decoder artefact (a no-op).  Drop it when another
        # real definition of the temp exists, or when the temp has no
        # readers at all (the dead-store branch below); keeping the only
        # definition of a later-read temp avoids an undefined-read artefact.
        self_lines = [
            idx
            for idx in idxs
            if (m := _ASSIGN.match(lines[idx].rstrip("\r\n")))
            and m.group(3).strip() == var
        ]
        other_defs = [idx for idx in idxs if idx not in self_lines]
        if other_defs:
            drop.update(self_lines)
        # A temp with no readers at all: every assignment is dead.  Only
        # drop them when every right-hand side is side-effect-free.
        self_reads = sum(
            1
            for idx in idxs
            if (m := _ASSIGN.match(lines[idx].rstrip("\r\n")))
            and m.group(3).strip() == var
        )
        reads = counts.get(var, 0) - len(idxs) - self_reads

        def _uses_var(rhs: str) -> bool:
            return bool(re.search(re.escape(var) + r"\b", rhs))

        def kill(idx: int) -> None:
            if idx in drop:
                return
            line = lines[idx]
            m = _ASSIGN.match(line.rstrip("\r\n"))
            rhs = m.group(3)
            if _pure_rhs(rhs):
                drop.add(idx)
            elif not _uses_var(rhs):
                if _repeats_near(idx, rhs):
                    # the control statement the value was folded into
                    # evaluates the same expression itself; the staging
                    # statement is a duplicate, not a side effect to keep
                    drop.add(idx)
                else:
                    rewrite[idx] = (
                        m.group(1)
                        + rhs
                        + ";"
                        + ("\n" if line.endswith("\n") else "")
                    )

        if reads <= 0:
            # No reader at all.  Pure stores are dead; a store whose value
            # comes from a call/`new` still has to run for its side effects,
            # so keep the expression but drop the dead temp name
            # (`$V = $obj->m();` -> `$obj->m();`).
            for idx in idxs:
                kill(idx)
        # A definition overwritten by the next definition before any read
        # is dead unless the second RHS reads the temp.  Intervening
        # statements are fine when they stay in the same block and do not
        # read the temp (`$T75 = ...;` between two `$T74 = ...;`); branch
        # structure (`}`/`else`/`case`/`if`/loops) and reads block it.
        _ctrl = re.compile(
            r"^(?:\}|\{|else|elseif|case|default|catch|break|continue|return|"
            r"if|for|foreach|while|switch|do|try|throw|goto)\b"
        )
        eff = [i for i in idxs if i not in self_lines]
        for a, b in zip(eff, eff[1:]):
            blocked = False
            for k in range(a + 1, b):
                if k in self_lines:
                    continue
                s = lines[k].strip()
                if not s:
                    continue
                if re.search(re.escape(var) + r"\b", lines[k]):
                    blocked = True
                    break
                if _ctrl.match(s):
                    blocked = True
                    break
            if blocked:
                continue
            rhs_b = _ASSIGN.match(lines[b].rstrip("\r\n")).group(3)
            if _uses_var(rhs_b):
                continue
            kill(a)
    drop |= _multiline_dead_temps(lines)
    out: list[str] = []
    for idx, line in enumerate(lines):
        if idx in drop:
            continue
        out.append(rewrite.get(idx, line))
    return _inline_pure_temps("".join(out))


# ---- single-definition pure temp inlining ---------------------------------

_HD_RE = re.compile(r"<<<\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
_NAME_RE = re.compile(r"\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*")
_PARAM_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
_KW = frozenset(
    {
        "if", "elseif", "else", "while", "for", "foreach", "switch", "case",
        "default", "catch", "function", "fn", "array", "list", "isset",
        "empty", "unset", "echo", "print", "return", "new", "clone", "yield",
        "match", "use", "declare", "do", "try", "throw", "and", "or", "xor",
        "instanceof", "static", "global", "include", "include_once",
        "require", "require_once", "eval",
    }
)


def _scan_spans(line: str, state: dict) -> list[tuple[int, int]]:
    """The code (non-string/comment) spans of one line.

    State is carried across lines for block comments, quoted strings and
    heredocs; the emitted files contain all three, so brace counting and
    temp substitution must not see their contents."""
    spans: list[tuple[int, int]] = []
    n = len(line)
    i = 0
    if state.get("heredoc"):
        lab = state["heredoc"]
        st = line.lstrip()
        if not st.startswith(lab) or (
            len(st) > len(lab) and (st[len(lab)].isalnum() or st[len(lab)] == "_")
        ):
            return spans
        # the closing label may be followed by more code on the same line
        # (`EOT) . _('...') . "...";` — PHP 7.3+ flexible heredoc); resume
        # the code scan after the label instead of masking the rest of the
        # file as heredoc body
        state["heredoc"] = None
        i = len(line) - len(st) + len(lab)
    quote = state.get("quote")
    if quote:
        while i < n:
            if line[i] == "\\":
                i += 2
                continue
            if line[i] == quote:
                i += 1
                quote = None
                break
            i += 1
        state["quote"] = quote
        if quote:
            return spans
    in_block = state.get("block", False)
    start = None
    while i < n:
        if in_block:
            j = line.find("*/", i)
            if j < 0:
                state["block"] = True
                return spans
            state["block"] = False
            in_block = False
            i = j + 2
            start = None
            continue
        ch = line[i]
        if ch in ("'", '"'):
            if start is not None:
                spans.append((start, i))
                start = None
            q = ch
            i += 1
            closed = False
            while i < n:
                if line[i] == "\\":
                    i += 2
                    continue
                if line[i] == q:
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                state["quote"] = q
            continue
        if ch == "/" and i + 1 < n and line[i + 1] == "*":
            if start is not None:
                spans.append((start, i))
                start = None
            j = line.find("*/", i + 2)
            if j < 0:
                state["block"] = True
                return spans
            i = j + 2
            continue
        if ch == "/" and i + 1 < n and line[i + 1] == "/":
            break
        if ch == "#":
            break
        if line.startswith("<<<", i):
            m = _HD_RE.match(line, i)
            if m:
                if start is not None:
                    spans.append((start, i))
                state["heredoc"] = m.group(1)
                return spans
        if start is None:
            start = i
        i += 1
    if start is not None:
        spans.append((start, n))
    return spans


def _mask_code(line: str, spans: list[tuple[int, int]]) -> str:
    chars = [" "] * len(line)
    for a, b in spans:
        chars[a:b] = line[a:b]
    return "".join(chars)


def _writes_var(code: str, name: str) -> bool:
    nm = re.escape(name)
    if re.search(
        r"\$"
        + nm
        + r"\b\s*(\[[^\]]*\]\s*)*(?:=(?![=>])|\+=|-=|\*=|/=|\.=|%=|&=|\|=|\^=|<<=|>>=|\?\?=)",
        code,
    ):
        return True
    if re.search(r"(\+\+|--)\s*\$" + nm + r"\b|\$" + nm + r"\b\s*(\+\+|--)",
                 code):
        return True
    if re.search(r"\bas\s+(&\s*)?\$" + nm + r"\b", code):
        return True
    if re.search(r"\b(list|unset|global|static)\s*\([^)]*\$" + nm + r"\b",
                 code):
        return True
    return False


def _calls_in(code: str) -> list[str]:
    return [
        m.group(1)
        for m in _CALL.finditer(code)
        if m.group(1).lower() not in _KW
    ]


def _inline_pure_temps(text: str) -> str:
    """Inline single-definition pure temps at their readers.

    A temp stored once from a side-effect-free expression and read later is
    inlined as `(<expr>)` when the definition is unconditionally executed
    relative to every reader (the brace depth never drops below the
    definition's depth), no variable the expression reads is written in
    between, and no side-effecting call sits in between.  This removes the
    decoder's `$Tn = ...` staging statements (`$T630 = $data['name'];
    switch ($T630)` -> `switch ($data['name'])`) without moving calls or
    duplicating side effects.
    """
    if not re.search(r"\$[TV]\d+\b", text):
        return text
    lines = text.splitlines(keepends=True)
    state: dict = {}
    masks: list[str] = []
    depths: list[int] = []
    depth = 0
    for line in lines:
        raw = line.rstrip("\r\n")
        spans = _scan_spans(raw, state)
        m = _mask_code(raw, spans)
        masks.append(m)
        depths.append(depth)
        depth += m.count("{") - m.count("}")
    defs: dict[str, list[tuple[int, str, int]]] = {}
    occ: dict[str, list[int]] = {}
    for idx, m in enumerate(masks):
        for x in _VAR.finditer(m):
            occ.setdefault(x.group(0), []).append(idx)
        am = _ASSIGN.match(m)
        if am:
            # the original text of the RHS.  The masked line blanks strings
            # to spaces, so `\s*` in the regex can eat the leading string:
            # locate the real `=` in the mask, then slice the original
            # columns up to the statement-ending semicolon.
            lhs_end = am.start(2) + len(am.group(2))
            eq = m.find("=", lhs_end)
            rhs = (
                lines[idx].rstrip("\r\n")[eq + 1 : am.end(3)].strip()
                if eq >= 0
                else ""
            )
            defs.setdefault(am.group(2), []).append((idx, rhs, am.start(1)))
    cands: dict[str, tuple[int, str, int]] = {}
    for var, ds in defs.items():
        if len(ds) != 1:
            continue
        d, rhs, indent = ds[0]
        if not rhs or re.search(re.escape(var) + r"\b", rhs):
            continue
        uses = [i for i in occ.get(var, []) if i != d]
        if not uses or any(i < d for i in uses):
            continue
        last = max(uses)
        if any(depths[i] < depths[d] for i in uses):
            continue
        if not _pure_rhs(rhs):
            # a call expression read once on the very next line can still
            # move: there is no intervening statement, and if the temp is
            # evaluated before any other call on that line the call order
            # relative to those calls is unchanged.  Nothing the expression
            # reads may be written before the temp's position either.
            if uses != [d + 1] or depths[uses[0]] != depths[d]:
                continue
            m_use = masks[uses[0]]
            pos = [
                mm.start()
                for mm in re.finditer(re.escape(var) + r"\b", m_use)
            ]
            if len(pos) != 1:
                continue
            names = set(_NAME_RE.findall(rhs))
            if any(_writes_var(m_use[: pos[0]], nm[1:]) for nm in names):
                continue
            first_call = next(
                (
                    mm.start()
                    for mm in _CALL.finditer(m_use)
                    if mm.group(1).lower() not in _KW
                ),
                None,
            )
            if first_call is not None and first_call < pos[0]:
                continue
            cands[var] = (d, rhs, indent)
            continue
        names = set(_NAME_RE.findall(rhs))
        use_set = set(uses)
        blocked = False
        for j in range(d + 1, last + 1):
            if depths[j] < depths[d]:
                blocked = True
                break
            if any(_writes_var(masks[j], nm[1:]) for nm in names):
                blocked = True
                break
            if j not in use_set and any(
                c.lstrip("\\") not in _SAFE_CALLS for c in _calls_in(masks[j])
            ):
                blocked = True
                break
        if not blocked:
            cands[var] = (d, rhs, indent)
    # a candidate whose expression reads another candidate cannot be
    # inlined (the referenced def line disappears) — drop the fixpoint
    changed = True
    while changed:
        changed = False
        for var in list(cands):
            rhs = cands[var][1]
            if any(
                re.search(re.escape(other) + r"\b", rhs)
                for other in cands
                if other != var
            ):
                del cands[var]
                changed = True
    if not cands:
        return text
    drop = {d for d, _rhs, _ind in cands.values()}
    out: list[str] = []
    for idx, line in enumerate(lines):
        if idx in drop:
            continue
        raw = line.rstrip("\r\n")
        reps: list[tuple[int, int, str]] = []
        for var, (_d, rhs, _ind) in cands.items():
            for m in re.finditer(re.escape(var) + r"\b", masks[idx]):
                reps.append((m.start(), m.end(), "(" + rhs + ")"))
        for a, b, rep in sorted(reps, reverse=True):
            raw = raw[:a] + rep + raw[b:]
        out.append(raw + ("\n" if line.endswith("\n") else ""))
    return "".join(out)


__all__ = ["drop_dead_pure_temps"]
