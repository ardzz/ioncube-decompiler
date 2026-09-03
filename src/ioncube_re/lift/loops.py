"""Control-flow shaping, part 2: loops — the while forms (head-tested via
structurer.emit_if, bottom-tested with condition priming, do-while) and
foreach (with the key-in-temp fold). The switch family lives in
switches.py.

The bottom-tested priming follows dawwinci's spec (structurer.py:296-345,
README.md:127-132): `JMP -> Lcond; body; Lcond: cond; J(N)Z -> body` renders
as the condition statement (the priming read), `while (<loop var>) { body;
<condition statement again> }` — the duplicated condition keeps the loop
variable advancing; semantically equivalent, and the only faithful shape a
bottom-tested loop with side-effect conditions can take without a goto.
"""

from __future__ import annotations

from .model import LoopInfo, LiftContext
from .operand import unwrap


def bottom_tested_while(ctx: LiftContext, i: int, t: int, end: int) -> int | None:
    """`JMP -> cond; body; cond; J(N)Z -> body_start` (the entry-JMP form;
    the generalization of the old loop-entry special case). Returns the
    next node index, or None when the shape does not hold."""
    from .emitter import emit_region

    b = i + 1  # body start: the fallthrough after the entry JMP
    if t <= i or t > end + 1 or b >= t:
        return None
    j = None
    for c in range(t, min(end + 1, ctx.thr)):
        o = ctx.op.get(c)
        if o in (43, 44) and ctx.jt.get(c) == b:
            j = c
            break
        if o in (46, 47):
            continue  # short-circuit inside the condition; keep scanning
        jt = ctx.jt.get(c)
        if jt is not None and jt < t:
            return None  # some other backward jump: not our pattern
    if j is None:
        return None
    # priming: the condition region renders first — a side-effect condition
    # ($row = fetch()) emits its statement here, a pure one emits nothing
    ctx.line(ctx.nodes[i])
    out0 = len(ctx.out)
    emit_region(ctx, t, j)
    primed = len(ctx.out) > out0
    condLine = ctx.curLine
    # the loop variable: when the conditional's temp was defined by an
    # ASSIGN to a CV, the while-condition renders that CV (dawwinci's
    # ASSIGN stores the target; the inlined value would re-call fetch())
    n_j = ctx.nodes[j]
    cond = ctx.render.ex_op1(n_j)
    eo = n_j.ent.get("op1")
    if eo and (eo.kind & 6):
        slot = n_j.op1 // 16
        es = ctx.effSlot.get(f"{j}:op1")
        if es is not None:
            slot = es
        d = ctx.tempDef.get(slot)
        if d is not None and t <= d < j and ctx.op[d] == 22:
            de = ctx.nodes[d].ent.get("op1")
            if de and de.kind == 8:
                cond = ctx.cv_name(de.raw)
    ctx.w(f"while ({unwrap(ctx.render.ch(cond))}) {{")
    ctx.idp += 1
    ctx.loop_stack.append(LoopInfo(frozenset({j + 1}), frozenset({t})))
    emit_region(ctx, b, t)
    if primed:
        # re-evaluate the condition at the end of the body so the loop
        # variable advances; the nodes were accounted in the priming pass,
        # so the counters and the line state are snapshotted (the duplicate
        # statement is a rendering, not a second node walk)
        saved = (ctx.emitted, ctx.bookkept, ctx.unknown, ctx.masked)
        ctx.curLine = condLine
        emit_region(ctx, t, j)
        ctx.emitted, ctx.bookkept, ctx.unknown, ctx.masked = saved
    ctx.loop_stack.pop()
    ctx.idp -= 1
    ctx.w("}")
    ctx.emitted += 1
    ctx.bk(j)
    return j + 1


def do_while_at(ctx: LiftContext, i: int, end: int) -> int | None:
    """`do { body } while (cond);` — a conditional back-edge targeting node
    i, reached by fallthrough (dawwinci structurer.py:235-242). The dw edge
    map is precomputed (model._calibrate_jumps); node i-1 being the entry
    JMP of a bottom-tested while excludes the pretested shape."""
    from .emitter import emit_region

    if ctx.op[i] == 42:
        return None  # a JMP is not a body start (the walker owns it)
    if i > 0 and ctx.op[i - 1] == 42 and ctx.jt.get(i - 1, 0) > i:
        return None  # a bottom-tested while owns this body (pretested)
    j = ctx.dw_edges.get(i)
    if j is None or j > end:
        return None
    # the condition defs sit between the body and the back-edge conditional
    c = j - 1
    n_j = ctx.nodes[j]
    eo = n_j.ent.get("op1")
    if eo and (eo.kind & 6):
        es = ctx.effSlot.get(f"{j}:op1")
        slot = es if es is not None else n_j.op1 // 16
        d = ctx.tempDef.get(slot)
        if d is not None and i <= d < j:
            c = d
    if c <= i:
        return None
    ctx.line(ctx.nodes[i])
    ctx.w("do {")
    ctx.idp += 1
    emit_region(ctx, i, c)
    emit_region(ctx, c, j)  # the condition defs (no output when pure)
    ctx.idp -= 1
    cond = unwrap(ctx.render.ch(ctx.render.ex_op1(n_j)))
    if ctx.op[j] == 43:  # JMPZ back edge: the loop repeats while !cond
        cond = "!(" + cond + ")"
    ctx.w(f"}} while ({unwrap(cond)});")
    ctx.emitted += 1
    ctx.bk(j)
    return j + 1


def emit_foreach(ctx: LiftContext, i: int, end: int) -> int:
    from .emitter import emit_region

    n = ctx.nodes[i]
    r = ctx.render
    exit_ = ctx.feExit.get(i)
    iter_ = r.ex_op1(n)
    f = ctx.nodes[i + 1] if i + 1 < ctx.thr else None
    if exit_ is None or iter_ is None or f is None or ctx.op[i + 1] not in (78, 126):
        ctx.w(f"/* n{i}: FE_RESET (unresolved) */")
        return i + 1
    byRef = ctx.op[i + 1] == 126  # FE_FETCH_RW: foreach (.. as &$v)
    val = r.ex(f, "op2")  # FE_FETCH op2 = value CV
    if byRef and val is not None:
        val = "&" + val
    keyName = None
    fe = f.ent.get("res")
    if fe and (fe.kind & 6):
        keySlot = f.res // 16
        if i + 2 < ctx.thr and ctx.op[i + 2] == 22:
            nx = ctx.nodes[i + 2]
            ne = nx.ent.get("op2")
            if ne and (ne.kind & 6) and nx.op2 // 16 == keySlot:
                keyName = r.ex_op1(nx)  # ASSIGN $k, T(key): the key-in-temp fold
    bodyStart = i + 3 if keyName is not None else i + 2
    if keyName is not None:
        ctx.bk(i + 2)
    back = None
    for j in range(bodyStart, exit_):
        # the LAST back-targeting JMP is the loop's own back edge — earlier
        # ones are `continue`s that must stay inside the body
        if ctx.op[j] == 42 and ctx.jt.get(j) == i + 1:
            back = j
    bodyEnd = back if back is not None else exit_
    ctx.bk(i + 1)  # the FE_FETCH_R
    if back is not None:
        ctx.bk(back)
    ctx.line(n)
    ctx.w(f"foreach ({r.ch(iter_)} as "
          + (keyName + " => " if keyName is not None else "") + r.ch(val) + ") {")
    ctx.idp += 1
    ctx.loop_stack.append(LoopInfo(frozenset({exit_, exit_ + 1}), frozenset({i + 1})))
    emit_region(ctx, bodyStart, bodyEnd)
    ctx.loop_stack.pop()
    ctx.idp -= 1
    ctx.w("}")
    ctx.emitted += 1
    return bodyEnd + 1  # FE_FREE at exit = bookkeeping


__all__ = ["bottom_tested_while", "do_while_at", "emit_foreach"]
