"""The switch family: reconstruction from the CASE/JMPNZ dispatch chain
(one encoder generation), the jumptable-header form (another generation's
IS_EQUAL+JMPNZ chains), and the jumptable fallback when the chain did not
reconstruct (the tables carry node targets directly on our build — the
one-opcode-late family is already calibrated at the jt layer).
"""

from __future__ import annotations

from ..serarr import decode_serarr
from .model import LoopInfo, LiftContext
from .operand import php_quote, unwrap

_CMP_CASE = (48, 194, 16, 18)  # CASE plus the IS_IDENTICAL/IS_EQUAL chain form
_CMP_HEADER = (48, 194, 16, 17, 18)  # + the other generations' header chains
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


def _loop_entry_jmp(ctx: LiftContext, k: int, t: int) -> bool:
    """A JMP that primes a bottom-tested loop: its target is the start of
    the loop condition, which soon reaches a conditional branch jumping
    back to the node after the JMP (`JMP -> cond; body; cond: Jcc -> body`).
    Such a JMP is not a switch arm break and its target is not the switch
    merge.
    """
    if t <= k or t >= ctx.thr:
        return False
    for j in range(t, min(t + 16, ctx.thr)):
        o = ctx.op.get(j)
        if o in (43, 44) and ctx.jt.get(j) == k + 1:
            return True
        if o in (42, 62, 79, 108):
            return False
    return False


def emit_switch(ctx: LiftContext, i: int, end: int, header: bool = False) -> int | None:
    """The switch reconstruction. header=True enters at the jumptable
    header (SWITCH_LONG/STRING) — the Part C path that also matches the
    other generation's IS_EQUAL+JMPNZ chains and falls back to the
    jumptable itself; header=False enters at the first CASE (the plain
    dispatch-chain form)."""
    from .emitter import emit_region

    cmp_ops = _CMP_HEADER if header else _CMP_CASE
    cases: list[dict] = []
    preludes: list[int] = []
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
                {
                    "val": ctx.render.ex_op2(c),
                    "target": ctx.jt[j + 1],
                    "caseNode": j,
                    "branch": o2,
                }
            )
            j += 2
            continue
        # operand prelude between two comparisons (a fetched constant used
        # by the next IS_IDENTICAL/IS_EQUAL): defer its temp def until the
        # chain is committed (a speculative scan that rejects the chain —
        # an if-condition CASE chain from _binop — must leave no output)
        if (
            o1 not in cmp_ops
            and j + 2 < end
            and ctx.op.get(j + 1) in cmp_ops
            and ctx.op.get(j + 2) in _COND_JUMPS
        ):
            preludes.append(j)
            j += 1
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
    if not cases:
        if not header:
            return None
        cases, default_target = _table_pairs(ctx, i)
        if cases is None:
            return None
        stop = j = i + 1
    if not header and cases:
        # The dispatch form matches a case and jumps INTO its body (JMPNZ).
        # An if/else-if chain jumps AWAY on a false condition (JMPZ), and a
        # short-circuit operand uses the _EX forms — neither is a switch.
        if any(c["branch"] != 44 for c in cases):
            return None
    targets = [c["target"] for c in cases]
    minT = min(targets)
    maxT = max(targets)
    if default_target is not None and default_target == minT:
        # 00441 lowering: the no-match chain terminal jumps to the first
        # case body as a placeholder (the loader patches the real merge),
        # not to a default arm — a real default body never reuses the
        # first case's target
        default_target = None
    if minT <= stop:
        return None
    # the subject temp's def statement was just emitted immediately before
    # the chain; the switch head inlines the expression and every reader is
    # the chain machinery, so the `$Tn = ...;` line is dead (a corpus
    # file's `$T58 = $type[1];` before every type switch)
    sn = ctx.nodes[i]
    so = sn.ent.get("op1")
    subj_slot0 = sn.op1 // 16 if so is not None and (so.kind & 6) else None
    if subj_slot0 is not None and ctx.tempDef.get(subj_slot0) == i - 1:
        caseNodes0 = {c["caseNode"] for c in cases if c["caseNode"] is not None}
        allowed = caseNodes0 | ({i} if header else set())
        uses0 = ctx.tempUses.get(subj_slot0, [])
        if (
            uses0
            and set(uses0) <= allowed
            and subj_slot0 in ctx.tempExpr
            and ctx.out
        ):
            dn = ctx.nodes[i - 1]
            de = dn.ent.get("res")
            if (
                de is not None
                and (de.kind & 6)
                and dn.res // 16 == subj_slot0
                and ctx.out[-1].strip()
                == (
                    ctx.temp_name(subj_slot0, de.kind)
                    + " = "
                    + unwrap(ctx.tempExpr[subj_slot0])
                    + ";"
                )
            ):
                ctx.out.pop()
    if preludes:
        from .emitter import emit_node

        for p in preludes:
            emit_node(ctx, p, end)
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
    # switch end: the furthest forward JMP out of the case bodies, then the
    # subject temp's canonical FREE on that exit path.  Early-return paths
    # inside a case also FREE the subject (one observed switch frees it at
    # node 20 before the first case body's return); scanning from the first
    # case start would mistake that for the switch end and re-emit the body.
    X = maxT + 1
    # A cluster of labels sharing one body (`case 'a': case 'b': ...`) has a
    # single case target, so maxT+1 is still inside that body.  The dispatch
    # chain's no-match JMP already points past the case bodies — at the merge
    # (no default arm) or at the default body — so include it in the scan
    # window instead of ending the switch at the first body node.  Stop AT
    # the target: when it is the merge, the case-break JMPs point there too;
    # when it is a default body, their targets beyond it widen the window.
    if default_target is not None and default_target > X:
        X = default_target
    anchored = False
    while True:
        cand = X
        for k in range(minT, X):
            if ctx.op.get(k) == 42:
                t = ctx.jt.get(k, -1)
                if t > k and t >= X:
                    # a body JMP reaches the current end: the bound holds
                    anchored = True
                if t > k and t > cand:
                    cand = t
        if cand == X:
            break
        X = cand
    switchEnd = X
    if not anchored:
        # every earlier case falls through (no break reached past the last
        # case start): the last body ends at its exit JMP / terminator
        for k in range(maxT, min(end, ctx.thr)):
            if ctx.op.get(k) == 42:
                t = ctx.jt.get(k, -1)
                if t > k and t < ctx.thr and ctx.op.get(t) in (62, 79, 108):
                    switchEnd = max(switchEnd, t)
                break
            if k > maxT and ctx.op.get(k) in (62, 79, 108):
                switchEnd = max(switchEnd, k)
                break
    # This lowering writes case-break JMPs as placeholders targeting the
    # next case body, so nothing targets the merge.  The remaining anchors
    # are the function epilogue after the last body.
    def _epilogue_tail(start: int) -> bool:
        for kk in range(start, ctx.thr):
            oo = ctx.op.get(kk)
            if oo in (62, 124):
                continue
            if oo == 42 and ctx.op.get(ctx.jt.get(kk, -1)) in (62, 124):
                continue
            return False
        return True

    if switchEnd <= maxT + 1:
        # a last body ending in an unconditional EXIT/THROW: the shared
        # epilogue starts right after it
        for kk in range(maxT, ctx.thr):
            if ctx.op.get(kk) in (79, 108) and _epilogue_tail(kk + 1):
                switchEnd = kk + 1
                break
    if switchEnd <= maxT + 1:
        # otherwise a case JMP to the trailing function RETURN marks the
        # merge (`case ...: ...; break;` at the end of a method); only an
        # epilogue-tail target qualifies, so an early return in the body
        # cannot truncate it
        for kk in range(maxT, ctx.thr):
            if ctx.op.get(kk) == 42:
                t = ctx.jt.get(kk, -1)
                if t > kk and ctx.op.get(t) in (62, 124) and _epilogue_tail(t):
                    switchEnd = t
                    break
    if subj_slot is not None:
        freeAt = None
        for k in range(maxT, min(X, ctx.thr - 1) + 1):
            if ctx.op[k] in (70, 127) and ctx.nodes[k].op1 // 16 == subj_slot:
                freeAt = k
        if freeAt is not None:
            switchEnd = freeAt
    if len(cases) == 1:
        # A lone case has no next case target to bound its body; the case
        # body's own break JMP (and the default arm's) point at the switch
        # merge.  Inner conditionals emit their own forward JMPs, so take
        # the furthest forward target in the region rather than the first.
        for k in range(maxT, min(end, ctx.thr)):
            if ctx.op.get(k) == 42:
                t = ctx.jt.get(k, -1)
                if switchEnd < t <= end:
                    switchEnd = t
    if (
        default_target is not None
        and subj_slot is not None
        and 0 <= default_target < ctx.thr
        and ctx.op.get(default_target) in (70, 127)
        and ctx.nodes[default_target].op1 // 16 == subj_slot
    ):
        # No `default:` arm: the dispatch chain's no-match JMP lands on the
        # subject's FREE on the post-switch path — that FREE is the switch
        # merge, and the statements after it stay outside the switch.
        switchEnd = default_target
    if default_target is not None and default_target > maxT:
        # The default arm is the last one.  If it contains a loop-entry JMP
        # whose condition lies at/after the computed switch end, the bound
        # cuts the loop (the loop target was mistaken for the merge); the
        # default body continues to the enclosing region end.  A break from
        # another arm must skip that body, so keeping it outside the switch
        # would be wrong.
        for k in range(default_target, min(end, ctx.thr)):
            if ctx.op.get(k) != 42:
                continue
            t = ctx.jt.get(k, -1)
            if _loop_entry_jmp(ctx, k, t) and t == switchEnd:
                switchEnd = min(end, ctx.thr)
                break
    entries = [
        (
            # re-render at emission time: a case value fetched by an operand
            # prelude is only inlinable once the prelude temp def exists
            ctx.render.ex_op2(ctx.nodes[c["caseNode"]])
            if c["caseNode"] is not None
            else c["val"],
            c["target"],
            c["caseNode"],
        )
        for c in cases
    ]
    if default_target is not None and stop <= default_target < switchEnd:
        entries.append((None, default_target, None))
    entries.sort(key=lambda e: e[1])
    # A switch whose arms all assign one temp and whose merge node is
    # `$dest = $temp` can write each arm straight to $dest: this drops the
    # shared temp and the trailing assignment (the switch-result lowering).
    resultSlot = None
    resultLhs = None
    consumeAssign = False
    switchReturnSlot = None
    if switchEnd < ctx.thr and ctx.op.get(switchEnd) == 62:
        rn = ctx.nodes[switchEnd]
        r1 = rn.ent.get("op1")
        if r1 is not None and (r1.kind & 6):
            rslot = rn.op1 // 16
            if (
                ctx.tempUses.get(rslot) == [switchEnd]
                and getattr(ctx, "tempDefCount", {}).get(rslot, 0) > 1
            ):
                # every arm writes one temp and the merge returns it:
                # lower each arm to its own `return <expr>;`
                switchReturnSlot = rslot
                ctx.meta["switchReturnSlot"] = switchReturnSlot
    if switchEnd < ctx.thr and ctx.op.get(switchEnd) == 22:
        an = ctx.nodes[switchEnd]
        a1, a2 = an.ent.get("op1"), an.ent.get("op2")
        if a1 is not None and a1.kind == 8 and a2 is not None and (a2.kind & 6):
            rslot = an.op2 // 16
            if (
                ctx.tempUses.get(rslot) == [switchEnd]
                and getattr(ctx, "tempDefCount", {}).get(rslot, 0) > 1
            ):
                resultSlot = rslot
                resultLhs = ctx.cv_name(a1.raw)
                consumeAssign = True
                ctx.meta["switchResultSlot"] = resultSlot
                ctx.meta["switchResultLhs"] = resultLhs
    sortedT = [e[1] for e in entries]
    lineNode = (
        ctx.nodes[cases[0]["caseNode"]]
        if cases and cases[0]["caseNode"] is not None
        else ctx.nodes[i]
    )
    ctx.line(lineNode)
    ctx.w("switch (" + unwrap(ctx.render.ch(subj)) + ") {")
    ctx.idp += 1
    bodyEnds = [
        sortedT[k + 1] if k + 1 < len(entries) else switchEnd
        for k in range(len(entries))
    ]
    # A JMP that ends an arm usually targets the next arm's body start in
    # this lowering (the loader patches the real merge): render it as the
    # arm's break so the cases do not fall through
    armBreaks = frozenset({switchEnd} | set(bodyEnds))
    ctx.loop_stack.append(LoopInfo(armBreaks, frozenset()))
    for k, (val, target, caseNode) in enumerate(entries):
        bodyEnd = bodyEnds[k]
        ctx.w("case " + ctx.render.ch(val) + ":" if val is not None else "default:")
        ctx.idp += 1
        emit_region(ctx, target, max(target, bodyEnd))
        # This lowering points an arm's terminal break at the next arm's
        # placeholder/FREE, not always at the merge.  A JMP that ends the
        # arm and leaves it is still a break, so the following case does
        # not fall through into this arm's body.
        if bodyEnd > target and ctx.op.get(bodyEnd - 1) == 42:
            t = ctx.jt.get(bodyEnd - 1, -1)
            if t >= bodyEnd and not (
                ctx.out and ctx.out[-1].strip().startswith("break")
            ):
                ctx.w("break;")
                ctx.bk(bodyEnd - 1)
        ctx.idp -= 1
        if caseNode is not None:
            ctx.bk(caseNode)
            ctx.bk(caseNode + 1)
    ctx.loop_stack.pop()
    ctx.idp -= 1
    ctx.w("}")
    ctx.emitted += 1
    if resultSlot is not None:
        ctx.meta.pop("switchResultSlot", None)
        ctx.meta.pop("switchResultLhs", None)
    if switchReturnSlot is not None:
        ctx.meta.pop("switchReturnSlot", None)
    if header:
        ctx.bk(i)
    if switchReturnSlot is not None:
        ctx.bk(switchEnd)
        return switchEnd + 1
    if consumeAssign:
        ctx.bk(switchEnd)
        return switchEnd + 1
    return min(switchEnd, end)


def _table_pairs(ctx: LiftContext, i: int):
    """The jumptable in the header's op2 (a const serarr zval) maps case
    values to NODE targets — one generation carries node indices directly.
    When the dispatch chain did not reconstruct, the table IS the chain
    (our tables are node-indexed, and the one-opcode-late family is
    already calibrated at the jt layer)."""
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


def emit_match_table(ctx: LiftContext, i: int, end: int) -> int | None:
    """Direct MATCH arm-table form -> strict switch over the table keys.

    The encoder lowers `match ($x) { 'a' => ..., default => ... }` to a
    MATCH node whose op2 is a serialized key->node table, followed by the
    arm bodies and their JMPs to the merge.  `match` compares with ``===``;
    a plain switch is loose, so emit ``switch (true)`` with ``subject ===
    key`` cases.  The subject expression is repeated per case (a listing
    simplification; the observed subjects are pure reads).
    """
    from .emitter import emit_region

    n = ctx.nodes[i]
    e = n.ent.get("op2")
    if not e or e.kind != 1 or e.raw >= len(ctx.zvals):
        return None
    z = ctx.zvals[e.raw]
    if (z.get("type", 0) & 0xFF) != 7 or "str" not in z:
        return None
    pairs = decode_serarr(z["str"])
    if not pairs:
        return None
    targets = []
    for _key, target in pairs:
        if not (isinstance(target, int) and i < target < ctx.thr):
            return None
        targets.append(target)
    uniq = sorted(set(targets))
    maxT = uniq[-1]
    # the first JMP after the last arm target is its terminal JMP to the
    # merge; the default arm starts immediately after it
    caseJmp = None
    for k in range(maxT, min(end, ctx.thr)):
        if ctx.op[k] == 42:
            raw = ctx.nodes[k].ent.get("op1")
            if raw is not None and raw.kind == 0 and raw.raw > maxT:
                caseJmp = k
                break
    if caseJmp is None:
        return None
    defaultStart = caseJmp + 1
    raw = ctx.nodes[caseJmp].ent["op1"].raw
    merge = ctx.jt.get(caseJmp, raw)
    if not (defaultStart < merge <= ctx.thr):
        # another generation stores the target node itself in the operand
        merge = raw
    if not (defaultStart < merge <= ctx.thr):
        return None
    # a subject FREE sits between the last arm and the merge consumer
    consumer = merge
    while consumer < ctx.thr and ctx.op.get(consumer) in (70, 127):
        consumer += 1
    if consumer >= ctx.thr:
        return None
    hasDefault = ctx.op.get(defaultStart) not in (70, 127)
    subj = n.ent.get("op1")
    subjSlot = n.op1 // 16 if subj is not None and (subj.kind & 6) else None
    freeK = None
    if subjSlot is not None:
        for k in range(consumer - 1, maxT - 1, -1):
            if ctx.op.get(k) not in (70, 127):
                continue
            e1 = ctx.nodes[k].ent.get("op1")
            if e1 is not None and (e1.kind & 6) and e1.raw == subjSlot:
                freeK = k
                break
    stop = freeK + 1 if freeK is not None else consumer
    # the merge consumer reads the match result from a temp; materialize
    # that temp inside the cases (QM_ASSIGN looks it up in ctx.meta)
    mergeNode = ctx.nodes[consumer]
    resultSlot = None
    for which in ("op1", "op2"):
        me = mergeNode.ent.get(which)
        if me is not None and (me.kind & 6):
            resultSlot = getattr(mergeNode, which) // 16
            break
    if resultSlot is None:
        return None
    # `return match (...) { ... };` — the merge reads the arm temp only to
    # return it: lower every arm to its own `return <expr>;` (the shape the
    # original source has) and consume the merge RETURN.
    returnMerge = ctx.op.get(consumer) == 62
    # `$dest = match (...) { ... };` — the merge assigns the arm temp to a
    # CV: write each arm straight to $dest and consume the merge ASSIGN.
    matchLhs = None
    if ctx.op.get(consumer) == 22:
        a1 = mergeNode.ent.get("op1")
        a2 = mergeNode.ent.get("op2")
        if (
            a1 is not None
            and a1.kind == 8
            and a2 is not None
            and (a2.kind & 6)
            and mergeNode.op2 // 16 == resultSlot
            and ctx.tempUses.get(resultSlot) == [consumer]
        ):
            matchLhs = ctx.cv_name(a1.raw)
    groups: dict[int, list] = {}
    for key, target in pairs:
        groups.setdefault(target, []).append(key)
    subjTxt = ctx.render.ch(ctx.render.ex_op1(n))
    prevResult = ctx.meta.get("matchResultSlot")
    prevReturn = ctx.meta.get("matchReturnSlot")
    prevLhs = ctx.meta.get("matchResultLhs")
    ctx.meta["matchResultSlot"] = resultSlot
    if returnMerge:
        ctx.meta["matchReturnSlot"] = resultSlot
    if matchLhs is not None:
        ctx.meta["matchResultLhs"] = matchLhs
    ctx.line(n)
    # match uses strict identity; switch(true) with === case expressions
    # preserves that (a plain switch would use loose ==)
    ctx.w("switch (true) {")
    ctx.idp += 1
    ctx.loop_stack.append(LoopInfo(frozenset({merge}), frozenset()))
    ends = uniq[1:] + [defaultStart if hasDefault else merge]
    for t, bodyEnd in zip(uniq, ends):
        for key in groups[t]:
            ktxt = (
                php_quote(key.encode("latin-1")) if isinstance(key, str) else str(key)
            )
            ctx.w("case (" + subjTxt + ") === " + ktxt + ":")
        ctx.idp += 1
        emit_region(ctx, t, min(bodyEnd, stop))
        # the arm's terminal JMP to the merge is a switch break; emit it
        # explicitly (the region emitter bookkeeps the JMP itself)
        if not (ctx.out and ctx.out[-1].strip() == "break;"):
            ctx.w("break;")
        ctx.idp -= 1
    if hasDefault:
        ctx.w("default:")
        ctx.idp += 1
        emit_region(ctx, defaultStart, stop)
        ctx.idp -= 1
    ctx.loop_stack.pop()
    ctx.idp -= 1
    ctx.w("}")
    if prevResult is None:
        ctx.meta.pop("matchResultSlot", None)
    else:
        ctx.meta["matchResultSlot"] = prevResult
    if matchLhs is not None:
        if prevLhs is None:
            ctx.meta.pop("matchResultLhs", None)
        else:
            ctx.meta["matchResultLhs"] = prevLhs
        for k in range(merge, consumer + 1):
            ctx.bk(k)
        ctx.emitted += 1
        ctx.bk(i)
        return consumer + 1
    if returnMerge:
        if prevReturn is None:
            ctx.meta.pop("matchReturnSlot", None)
        else:
            ctx.meta["matchReturnSlot"] = prevReturn
        for k in range(merge, consumer + 1):
            ctx.bk(k)
        ctx.emitted += 1
        ctx.bk(i)
        return consumer + 1
    for k in range(merge, consumer):
        ctx.bk(k)
    ctx.emitted += 1
    ctx.bk(i)
    return stop


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


__all__ = [
    "emit_case",
    "emit_match",
    "emit_match_table",
    "emit_switch",
    "emit_switch_header",
]
