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

_CMP_CASE = (48, 194)  # the CE generation's dispatch comparisons
_CMP_HEADER = (48, 194, 18)  # + IS_EQUAL: the Blesta generation's form
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
    e = (
        "("
        + r.ch(r.ex_op1(n))
        + " "
        + ("===" if ctx.op[i] == 194 else "==")
        + " "
        + r.ch(r.ex_op2(n))
        + ")"
    )
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
    default_target: int | None = None
    j = i + 1 if header else i
    while j + 1 < end:
        o1, o2 = ctx.op[j], ctx.op[j + 1]
        if o1 in cmp_ops and o2 in _COND_JUMPS:
            c, z = ctx.nodes[j], ctx.nodes[j + 1]
            zo, cre = z.ent.get("op1"), c.ent.get("res")
            if not (
                zo
                and (zo.kind & 6)
                and cre
                and (cre.kind & 6)
                and z.op1 // 16 == c.res // 16
            ):
                break
            if j + 1 not in ctx.jt:
                break
            cases.append(
                {"val": ctx.render.ex_op2(c), "target": ctx.jt[j + 1], "caseNode": j}
            )
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
    lineNode = (
        ctx.nodes[cases[0]["caseNode"]]
        if cases and cases[0]["caseNode"] is not None
        else ctx.nodes[i]
    )
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
        cases.append(
            {
                "val": php_quote(str(val).encode("latin-1")),
                "target": target,
                "caseNode": None,
            }
        )
    return cases, None


def emit_match(ctx: LiftContext, i: int, end: int) -> int | None:
    """The PHP 8 match-expression lowering as the evaluation encoder emits
    it — NOT a CASE chain, so emit_switch does not recognize it:
      match(true):  [cmp][BOOL_NOT][JMPNZ->arm]... arms QM_ASSIGN + JMP merge
      match($enum): {[BIND_STATIC][JMP_NULL][JMPNZ]}xN, default
                    CHECK_UNDEF_ARGS, arms QM_ASSIGN + JMP merge, FREE(subject)
    The walk arrives here either at the first BIND_STATIC unit (P2) or at
    the BOOL_NOT of a P1 chain. The degradations render the arm table as a
    comment and assign null — the arm VALUES are exact, the conditions are
    not reconstructed (the eval keytable garbles the comparison opcodes),
    and the whole span is bookkept so no masked-node noise remains."""
    r = ctx.render

    def zstr(e) -> str | None:
        if e is not None and e.kind == 1 and e.raw < len(ctx.zvals):
            from .operand import zval_name

            nm = zval_name(ctx.zvals[e.raw])
            if nm is not None:
                return nm
        return None

    def arm_val(at: int) -> str | None:
        if ctx.op[at] == 31:
            return zstr(ctx.nodes[at].ent.get("op1"))
        return None

    if ctx.op[i] == 181:  # ---- P2: the enum/subject unit chain ----
        units: list[dict] = []
        j = i
        while (
            j + 2 < end
            and ctx.op[j] == 181
            and ctx.op[j + 1] == 196
            and ctx.op[j + 2] == 44
        ):
            bs, jn, br = ctx.nodes[j], ctx.nodes[j + 1], ctx.nodes[j + 2]
            bres = bs.ent.get("res")
            jres = jn.ent.get("res")
            bo1 = br.ent.get("op1")
            if not (
                bres
                and jres
                and bo1
                and (bres.kind & 2)
                and (jres.kind & 2)
                and (bo1.kind & 2)
                and jn.op2 // 16 == bs.res // 16
                and br.op1 // 16 == jn.res // 16
            ):
                return None
            # the branch target: the JMPNZ's op2 ENT raw (the -1 calibration
            # is consistent across every observed arm target); node.op2 is
            # the slot conv, not the target
            tgt = br.ent["op2"].raw - 1
            if not (i < tgt < ctx.thr):
                return None
            units.append(
                {
                    "cls": zstr(bs.ent.get("op1")),
                    "nm": zstr(bs.ent.get("op2")),
                    "tgt": tgt,
                    "nodes": (j, j + 1, j + 2),
                    "subjSlot": jn.op1 // 16,
                    "subjRaw": jn.ent["op1"].raw,
                }
            )
            j += 3
        if len(units) < 2:
            return None
        # the subject temp + its value expr (FETCH_OBJ_R before the chain)
        subjSlot = units[0]["subjSlot"]
        subjDef = ctx.tempDef.get(subjSlot)
        if subjDef is None or subjSlot not in ctx.tempExpr:
            return None
        subj = ctx.tempExpr[subjSlot]
        # group units by arm target: (cond members..., arm value)
        arms: dict[int, list[dict]] = {}
        for u in units:
            arms.setdefault(u["tgt"], []).append(u)
        # scan forward: arms' QM_ASSIGN/JMP runs, the default, the FREE
        armTexts: list[tuple[str, str]] = []
        for tgt, us in arms.items():
            v = arm_val(tgt)
            if v is None:
                return None
            cls = us[0]["cls"]
            nm = us[0]["nm"]
            cond = (
                " || ".join(f"{cls}::{u['nm']} === {subj}" for u in us)
                if cls and all(u["nm"] for u in us)
                else None
            )
            if cond is None:
                return None
            armTexts.append((cond, v))
        # the default arm + FREE: scan past the last arm target. A
        # CHECK_UNDEF_ARGS right after the chain is the no-default throw
        # path — a match may be exhaustive (gdiverse4 match2), so "no
        # default" is valid; the FREE(subject) is the reliable terminator.
        lastT = max(arms)
        armTargets = set(arms)
        k = lastT
        defaultVal = None
        freeK = None
        k = lastT + 1  # the arm at lastT was consumed by armTexts
        while k < min(end, ctx.thr):
            o = ctx.op[k]
            if o == 197:  # CHECK_UNDEF_ARGS — the no-default throw guard
                k += 1
                continue
            if o in (70, 127):
                fo = ctx.nodes[k].ent.get("op1")
                if fo and (fo.kind & 2) and fo.raw == units[0]["subjRaw"]:
                    freeK = k
                    k += 1
                    break
                k += 1
                continue
            if o == 31 and k not in armTargets and defaultVal is None:
                defaultVal = zstr(ctx.nodes[k].ent.get("op1"))
                k += 1
                continue
            if o in (42, 28):
                k += 1
                continue
            break
        if freeK is None:
            return None
        # the receiving CV (the ASSIGN right after the merge): res var
        recv = None
        mk = freeK + 1
        if ctx.op[mk] == 22:
            e1 = ctx.nodes[mk].ent.get("op1")
            if e1 and e1.kind == 8:
                recv = ctx.cv.get(e1.raw, f"CV{e1.raw}")
        parts = "; ".join(f"{c} => '{v}'" for c, v in armTexts)
        if defaultVal is not None:
            parts += f"; default => '{defaultVal}'"
        ctx.line(ctx.nodes[i])
        if recv:
            ctx.w(f"${recv} = /* match (degraded): {parts} */ null;")
        else:
            ctx.w(f"/* match (degraded): {parts} */")
        ctx.emitted += 1
        stop = (freeK + 1) if freeK is not None else (lastT + 1)
        if ctx.op[stop] == 22:
            # the merge ASSIGN (str = <arm temp>) is part of the lowering
            e2 = ctx.nodes[stop].ent.get("op2")
            e1 = ctx.nodes[stop].ent.get("op1")
            if e1 and e1.kind == 8 and e2 and e2.kind == 2:
                stop += 1
        for k2 in range(i, stop):
            ctx.bk(k2)
        return stop
    # ---- P1: match(true) — [cmp][BOOL_NOT|BOOL_XOR|=== true][JMPNZ] chain ----
    if ctx.op[i] not in (14, 15, 16):
        return None
    units = []
    j = i - 1  # the cmp behind the BOOL_NOT/BOOL_XOR/IS_IDENTICAL
    while (
        j >= 0 and j + 2 < end and ctx.op[j + 1] in (14, 15, 16) and ctx.op[j + 2] == 44
    ):
        cmpn, bn, br = ctx.nodes[j], ctx.nodes[j + 1], ctx.nodes[j + 2]
        cres, bres = cmpn.ent.get("res"), bn.ent.get("res")
        bo1 = br.ent.get("op1")
        if not (
            cres
            and bres
            and bo1
            and (cres.kind & 2)
            and (bres.kind & 2)
            and (bo1.kind & 2)
            and bn.op1 // 16 == cmpn.res // 16
            and br.op1 // 16 == bn.res // 16
        ):
            return None
        tgt = br.ent["op2"].raw - 1
        if not (0 < tgt < ctx.thr):
            return None
        units.append({"tgt": tgt, "cmp": j, "nodes": (j, j + 1, j + 2)})
        j = br.op2 - 1 - 2  # next cmp candidate: arm target - [QM][JMP]? no —
        break  # the chain's cmp nodes are NOT adjacent (arms interleave);
        # one unit suffices to anchor: collect the rest by walking the
        # JMPNZ targets forward instead
    if not units:
        return None
    # collect the full P1 chain forward from the anchor unit
    seen = {units[0]["cmp"]}
    queue = [units[0]]
    arms1: dict[int, list[int]] = {}
    for u in queue:
        tgt = u["tgt"]
        v = arm_val(tgt)
        if v is None:
            return None
        arms1.setdefault(tgt, []).append(u["cmp"])
        # the next chain unit may sit BEFORE this arm's body (the arms
        # interleave: [cmp][not][JMPNZ][QM arm][JMP merge][cmp2]...) —
        # scan a window around the arm target
        for cand in range(max(0, tgt - 4), min(tgt + 3, end - 2)):
            if (
                ctx.op[cand] == 44
                and cand - 2 >= 0
                and ctx.op[cand - 1] in (14, 15, 16)
                and cand - 3 >= 0
                and ctx.op[cand - 2] != 181
                and (cand - 2) not in seen
            ):
                cu = {
                    "tgt": ctx.nodes[cand].ent["op2"].raw - 1,
                    "cmp": cand - 2,
                    "nodes": (cand - 2, cand - 1, cand),
                }
                if (
                    isinstance(cu["tgt"], int)
                    and cu["tgt"] > cand
                    and cu["cmp"] not in seen
                ):
                    seen.add(cu["cmp"])
                    queue.append(cu)
    if len(arms1) < 2:
        return None
    units = list(queue)  # the queue collected the whole chain
    armParts = []
    for tgt, cmps in sorted(arms1.items()):
        v = arm_val(tgt)
        if v is None:
            return None
        armParts.append(v)
    # the default arm: the JMP that immediately follows the last chain
    # unit targets the default's QM_ASSIGN (the arms interleave:
    # [unit1][unit2][JMP default][QM arm1][JMP][QM arm2][JMP][QM default])
    lastUnit = units[-1]
    dv = None
    dtv = -1
    dj = lastUnit["nodes"][2] + 1
    if dj < end and ctx.op[dj] == 42:
        dt = ctx.nodes[dj].ent.get("op1")
        if dt is not None and dt.kind == 0:
            dtv = dt.raw - 1
            if 0 < dtv < ctx.thr:
                dv = arm_val(dtv)
    # the receiving CV: the ASSIGN whose op2 carries the arms' result temp
    # (the eval keytable garbles its opcode — match on the operand shape,
    # an op1 CV + an op2 T equal to the arm QM_ASSIGN's res). It sits at
    # the merge, right after the default arm's JMP.
    recv = None
    recvNode = None
    armRes = ctx.nodes[min(arms1)].ent.get("res")
    mergeStart = max(arms1)
    if dv is not None and dtv + 1 < ctx.thr and ctx.op[dtv + 1] == 42:
        mt = ctx.nodes[dtv + 1].ent.get("op1")
        if mt is not None and mt.kind == 0:
            mergeStart = mt.raw - 1
    for cand in range(mergeStart, min(mergeStart + 4, ctx.thr)):
        nn = ctx.nodes[cand]
        e1, e2 = nn.ent.get("op1"), nn.ent.get("op2")
        if (
            e1
            and e1.kind == 8
            and e2
            and e2.kind == 2
            and armRes
            and e2.raw == armRes.raw
        ):
            recv = ctx.cv.get(e1.raw, f"CV{e1.raw}")
            recvNode = cand
            break
    parts = " | ".join(f"'{v}'" for v in armParts)
    if dv is not None:
        parts += f" | default '{dv}'"
    ctx.line(ctx.nodes[units[0]["cmp"]])
    if recv:
        ctx.w(f"${recv} = /* match (degraded): {parts} */ null;")
    else:
        ctx.w(f"/* match (degraded): {parts} */")
    ctx.emitted += 1
    stop = max(max(arms1) + 2, units[-1]["nodes"][2] + 1)
    if recvNode is not None:
        stop = max(stop, recvNode + 1)
    for k2 in range(units[0]["cmp"], stop):
        ctx.bk(k2)
    return stop


__all__ = ["emit_case", "emit_match", "emit_switch", "emit_switch_header"]
