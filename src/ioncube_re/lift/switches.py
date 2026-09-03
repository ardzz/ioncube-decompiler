"""The switch family: reconstruction from the CASE/JMPNZ dispatch chain
(the CE generation), the jumptable-header form (the Blesta generation's
IS_EQUAL+JMPNZ chains), and the jumptable fallback when the chain did not
reconstruct (the tables carry node targets directly on our build — the
dawwinci stride-inference repair is unnecessary: the one-opcode-late
family is already calibrated at the jt layer, DAWWINCI-DIFF §4.4).
"""

from __future__ import annotations

from ..serarr import decode_serarr
from .model import LoopInfo, LiftContext
from .operand import php_quote, unwrap

_CMP_CASE = (48, 194)          # the CE generation's dispatch comparisons
_CMP_HEADER = (48, 194, 18)    # + IS_EQUAL: the Blesta generation's form
_COND_JUMPS = (43, 44, 46, 47)


def emit_switch_header(ctx: LiftContext, i: int, end: int) -> int:
    """SWITCH_LONG/SWITCH_STRING (incl. the ungarbled +2 forms): try the
    header-driven switch reconstruction; the bare header degrades to
    bookkeeping (the jumptable fast-path renders nothing — its op2
    duplicates the CASE/IS_EQUAL chain that follows)."""
    sw = emit_switch(ctx, i, end, header=True)
    if sw is not None:
        return sw
    ctx.bk(i)
    return i + 1


def emit_case(ctx: LiftContext, i: int, end: int) -> int:
    """CASE / CASE_STRICT: the chain reconstructs a switch, else the node
    degrades to the equality comparison defTemp."""
    sw = emit_switch(ctx, i, end, header=False)
    if sw is not None:
        return sw
    n = ctx.nodes[i]
    r = ctx.render
    e = "(" + r.ch(r.ex_op1(n)) + " " + ("===" if ctx.op[i] == 194 else "==") \
        + " " + r.ch(r.ex_op2(n)) + ")"
    return ctx.def_temp(n, e, i)


def emit_switch(ctx: LiftContext, i: int, end: int, header: bool = False) -> int | None:
    """The switch reconstruction. header=True enters at the jumptable
    header (SWITCH_LONG/STRING) — the Part C path that also matches the
    Blesta generation's IS_EQUAL+JMPNZ chains and falls back to the
    jumptable itself; header=False enters at the first CASE (the CE
    form, the pre-Part-C behavior)."""
    from .emitter import emit_region

    cmp_ops = _CMP_HEADER if header else _CMP_CASE
    cases: list[dict] = []
    default_target = None
    j = i + 1 if header else i
    while j + 1 < end:
        o1, o2 = ctx.op[j], ctx.op[j + 1]
        if o1 in cmp_ops and o2 in _COND_JUMPS:
            c, z = ctx.nodes[j], ctx.nodes[j + 1]
            zo, cre = z.ent.get("op1"), c.ent.get("res")
            if not (zo and (zo.kind & 6) and cre and (cre.kind & 6)
                    and z.op1 // 16 == c.res // 16):
                break
            if j + 1 not in ctx.jt:
                break
            cases.append({"val": ctx.render.ex_op2(c), "target": ctx.jt[j + 1],
                          "caseNode": j})
            j += 2
            continue
        if cases and o1 == 42 and j in ctx.jt:
            # the chain-terminal JMP = the default branch
            default_target = ctx.jt[j]
            if header:
                ctx.bk(j)
            j += 1
            break
        break
    stop = j - 1 if default_target is not None and j > i and ctx.op[j - 1] == 42 else j
    if len(cases) < 2:
        if not header:
            return None
        cases, default_target = _table_pairs(ctx, i)
        if cases is None:
            return None
        stop = j = i + 1
    targets = [c["target"] for c in cases]
    minT = min(targets)
    maxT = max(targets)
    if minT <= stop:
        return None
    # the subject: the header's op1 (header form) or the first CASE's op1;
    # a temp subject inlines when its only uses are the chain's nodes
    subj = None
    subj_slot = None
    if header:
        hn = ctx.nodes[i]
        subj = ctx.render.ex_op1(hn)
        ho = hn.ent.get("op1")
        if ho and (ho.kind & 6):
            subj_slot = hn.op1 // 16
            es = ctx.effSlot.get(f"{i}:op1")
            if es is not None:
                subj_slot = es
            caseNodes = {c["caseNode"] for c in cases if c["caseNode"] is not None}
            uses = ctx.tempUses.get(subj_slot, [])
            if uses and set(uses) <= (caseNodes | {i}) and subj_slot in ctx.tempExpr:
                subj = ctx.tempExpr[subj_slot]
    else:
        subj = ctx.render.ex_op1(ctx.nodes[i])
        ho = ctx.nodes[i].ent.get("op1")
        if ho and (ho.kind & 6):
            subj_slot = ctx.nodes[i].op1 // 16
            caseNodes = {c["caseNode"] for c in cases}
            uses = ctx.tempUses.get(subj_slot, [])
            if uses and set(uses) <= caseNodes and subj_slot in ctx.tempExpr:
                subj = ctx.tempExpr[subj_slot]
    if subj is None:
        subj = ctx.render.ex_op1(ctx.nodes[i])
    # switch end: the subject temp's FREE when one exists (php-src frees the
    # subject right after the dispatch), else the furthest-forward JMP out of
    # the case bodies (dawwinci _find_subject_free / _infer_switch_end)
    switchEnd = None
    if subj_slot is not None:
        for k in range(stop, min(end, ctx.thr - 1) + 1):
            if ctx.op[k] in (70, 127) and ctx.nodes[k].op1 // 16 == subj_slot:
                switchEnd = k
                break
    if switchEnd is None:
        # fixpoint: the switch end grows only from JMPs that EXIT from
        # inside the current span — post-switch jumps are never scanned
        X = maxT + 1
        while True:
            cand = X
            for k in range(minT, X):
                if ctx.op.get(k) == 42:
                    t = ctx.jt.get(k, -1)
                    if t > k and t > cand:
                        cand = t
            if cand == X:
                break
            X = cand
        switchEnd = X
    entries = [(c["val"], c["target"], c["caseNode"]) for c in cases]
    if default_target is not None and stop <= default_target < switchEnd:
        entries.append((None, default_target, None))
    entries.sort(key=lambda e: e[1])
    sortedT = [e[1] for e in entries]
    lineNode = ctx.nodes[cases[0]["caseNode"]] if cases and cases[0]["caseNode"] is not None \
        else ctx.nodes[i]
    ctx.line(lineNode)
    ctx.w("switch (" + unwrap(ctx.render.ch(subj)) + ") {")
    ctx.idp += 1
    ctx.loop_stack.append(LoopInfo(frozenset({switchEnd}), frozenset()))
    for k, (val, target, caseNode) in enumerate(entries):
        bodyEnd = sortedT[k + 1] if k + 1 < len(entries) else switchEnd
        ctx.w("case " + ctx.render.ch(val) + ":" if val is not None else "default:")
        ctx.idp += 1
        emit_region(ctx, target, max(target, bodyEnd))
        ctx.idp -= 1
        if caseNode is not None:
            ctx.bk(caseNode)
            ctx.bk(caseNode + 1)
    ctx.loop_stack.pop()
    ctx.idp -= 1
    ctx.w("}")
    ctx.emitted += 1
    if header:
        ctx.bk(i)
    return min(switchEnd, end)


def _table_pairs(ctx: LiftContext, i: int):
    """The jumptable in the header's op2 (a const serarr zval) maps case
    values to NODE targets — the Blesta generation carries node indices
    directly (verified: license.php setError's table == the JMPNZ chain
    targets). When the dispatch chain did not reconstruct, the table IS
    the chain (the dawwinci jump-table repair, their stride-inference
    variant is unnecessary here: our tables are node-indexed, and the
    one-opcode-late family is already calibrated at the jt layer)."""
    n = ctx.nodes[i]
    e = n.ent.get("op2")
    if not e or e.kind != 1 or e.raw >= len(ctx.zvals):
        return None, None
    z = ctx.zvals[e.raw]
    if (z.get("type", 0) & 0xFF) != 7 or "str" not in z:
        return None, None
    pairs = decode_serarr(z["str"])
    if not pairs or len(pairs) < 2:
        return None, None
    cases = []
    for val, target in pairs:
        if not (isinstance(target, int) and i + 1 < target < ctx.thr):
            return None, None
        cases.append({"val": php_quote(str(val).encode("latin-1")),
                      "target": target, "caseNode": None})
    return cases, None


__all__ = ["emit_case", "emit_switch", "emit_switch_header"]
