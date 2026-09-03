"""Control-flow shaping, part 1: try/catch, return, jumps (incl. the Part C
break/continue levels and the --valid-php goto-label fallback), if/else
with the &&/|| short-circuit merge and the Part C ternary folding. Loops
and switches live in loops.py / switches.py — emit_jmp delegates to them.
"""

from __future__ import annotations

from ..opcodes import OPNAMES
from .model import LoopInfo, LiftContext, _PLUMBING, _PURE
from .operand import bare, unwrap

# the region between a short-circuit jump and its target must hold only
# these pure expression defs for the &&/|| merge to fire (emitIf's set,
# plus the FETCH family — a short-circuit's right term legally fetches:
# `$_SERVER['REQUEST_METHOD'] == 'POST' && empty($_POST)`)
_SC_PURE = frozenset(range(1, 22)) | {31, 51, 52, 53, 114, 115, 121, 123,
                                      138, 148, 154, 169, 170, 188, 191} \
    | frozenset(range(80, 99))


def loop_exit_stmt(ctx: LiftContext, target: int) -> str | None:
    """break;/continue; with level (dawwinci structurer.py:244-250)."""
    for depth, loop in enumerate(reversed(ctx.loop_stack), start=1):
        if target in loop.break_targets:
            return "break;" if depth == 1 else f"break {depth};"
        if target in loop.continue_targets:
            return "continue;" if depth == 1 else f"continue {depth};"
    return None


def emit_try(ctx: LiftContext, i: int, tb: tuple[int, int]) -> int:
    from .emitter import emit_region

    s, h = tb
    ctx.tryBlocks = [x for x in ctx.tryBlocks if x != tb]
    catchEntry = h - 1  # catch-skip JMP before the CATCH bind
    after = ctx.jt.get(catchEntry, min(h + 8, ctx.thr))
    catchN = ctx.nodes[h]
    cls = bare(ctx.render.ch(ctx.render.ex_op1(catchN)))
    e = catchN.ent.get("res")
    var = (ctx.cv_name(e.raw) if e and e.kind == 8 else "$e?")
    ctx.line(ctx.nodes[s])
    ctx.w("try {")
    ctx.idp += 1
    emit_region(ctx, s, catchEntry)
    ctx.idp -= 1
    ctx.bk(catchEntry)
    ctx.w(f"}} catch ({cls} {var}) {{")
    ctx.idp += 1
    emit_region(ctx, h, after)
    ctx.idp -= 1
    ctx.w("}")
    return after


def emit_return(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    v = ctx.render.ex_op1(n)
    isNull = v is None or v == "null"
    if i == ctx.thr - 1 and (isNull or (ctx.isMain and v == "1")):
        ctx.bookkept += 1  # implicit final return
        return i + 1
    ctx.line(n)
    ctx.w("return " + ("" if isNull else unwrap(ctx.render.ch(v))) + ";")
    ctx.emitted += 1
    return i + 1


def emit_jmp(ctx: LiftContext, i: int, end: int) -> int:
    from . import loops

    n = ctx.nodes[i]
    t = ctx.jt.get(i)
    if t is None:
        ctx.w(f"/* n{i}: JMP (unresolved target) */")
        return i + 1
    if ctx.op[t] == 62:  # mid-function return compiled as JMP
        return _jmp_return(ctx, i, t, t, end, f" -> n{t}")
    if ctx.op[t] == 124 and ctx.op.get(t + 1) == 62:  # VERIFY+RETURN epilogue
        return _jmp_return(ctx, i, t + 1, t, end, f" -> epilogue n{t}")
    # (Part C) break/continue against the loop/switch stack
    stmt = loop_exit_stmt(ctx, t)
    if stmt is not None:
        ctx.line(n)
        ctx.w(stmt)
        ctx.emitted += 1
        return i + 1
    if t > i and t <= end + 1:
        # bottom-tested while (with priming) — the generalization of the
        # old loop-entry form; loops.py owns it
        bt = loops.bottom_tested_while(ctx, i, t, end)
        if bt is not None:
            return bt
    if t < i:
        ctx.w(f"/* n{i}: JMP -> n{t} (loop back-edge) */")
        return i + 1
    # forward unstructured jump: the faithful comment (default), or the
    # --valid-php goto-label fallback (runnable output, unfaithful shape)
    if ctx.valid_php:
        ctx.goto_targets.add(t)
        ctx.line(n)
        ctx.w(f"goto label_{t};")
        ctx.emitted += 1
        return i + 1
    ctx.w(f"/* n{i}: JMP -> n{t} */")
    return i + 1


def _jmp_return(ctx: LiftContext, i: int, tnode: int, ret: int, end: int, tag: str) -> int:
    n = ctx.nodes[i]
    tn = ctx.nodes[tnode]
    v = ctx.render.ex_op1(tn)
    isNull = v is None or v == "null"
    ctx.line(n)
    ctx.w(f"return {'' if isNull else unwrap(ctx.render.ch(v))}; /*{tag} */")
    ctx.emitted += 1
    return ret if ret < end else end


def _pure_arm(ctx: LiftContext, lo: int, hi: int) -> int | None:
    """[lo, hi) is a non-empty expression arm ending in a QM_ASSIGN: pure
    defs (op in _PURE with a res temp) and the call machinery (op in
    _PLUMBING / CHECK_FUNC_ARG — collect_call/collect_new consume their
    chains without emitting statements). Returns the arm's QM_ASSIGN result
    slot, or None when the shape does not hold."""
    if hi <= lo:
        return None
    if ctx.op[hi - 1] != 31:
        return None
    ln = ctx.nodes[hi - 1]
    le = ln.ent.get("res")
    if not le or not (le.kind & 6):
        return None
    for k in range(lo, hi):
        o = ctx.op[k]
        if o in _PLUMBING or o == 100:
            continue
        ne = ctx.nodes[k].ent.get("res")
        if o not in _PURE or not ne or not (ne.kind & 6):
            return None
    return ln.res // 16


def _ternary_arms(ctx: LiftContext, i: int, t: int, skip: int) -> tuple[int, str, str] | None:
    """The then arm [i+1, t-1) and else arm [t, skip) of a JMPZ shape, when
    both end in a QM_ASSIGN into the same result slot and nothing reads
    that slot before ``skip``: emit both arm regions (expression defs only)
    and return (slot, then_expr, else_expr). None when the shape does not
    hold."""
    from .emitter import emit_region

    if t <= i + 1 or skip <= t:
        return None
    slot = _pure_arm(ctx, i + 1, t - 1)
    if slot is None or _pure_arm(ctx, t, skip) != slot:
        return None
    if any(u < skip for u in ctx.tempUses.get(slot, [])):
        return None  # an inner read: the slot is not the ternary result
    emit_region(ctx, i + 1, t - 1)
    a = ctx.tempExpr.get(slot)
    emit_region(ctx, t, skip)
    b = ctx.tempExpr.get(slot)
    if a is None or b is None:
        return None
    return slot, a, b


def _sc_pure_region(ctx: LiftContext, lo: int, hi: int) -> bool:
    """[lo, hi) holds only expression defs for a short-circuit merge:
    pure defs (op in _SC_PURE with a res temp), the call machinery
    (_PLUMBING — the collectors render it into tempExpr without a
    statement), and NESTED short-circuit jumps (JMPZ_EX/JMPNZ_EX at k
    whose own right operand [k+1, jt[k)) is itself merge-pure — the
    `a || (b && c)` lowering, EmailsController emailtemplateAction
    n136-146)."""
    k = lo
    while k < hi:
        o = ctx.op[k]
        if o in _PLUMBING:
            k += 1
            continue
        if o in (46, 47):
            m = ctx.jt.get(k)
            if m is None or not (k + 1 < m <= hi):
                return False
            if not _sc_pure_region(ctx, k + 1, m):
                return False
            k = m
            continue
        ne = ctx.nodes[k].ent.get("res")
        if not ne or not (ne.kind & 6) or o not in _SC_PURE:
            return False
        k += 1
    return True


def emit_if(ctx: LiftContext, i: int, end: int, op: int) -> int:
    from .emitter import emit_region

    n = ctx.nodes[i]
    r = ctx.render
    t = ctx.jt.get(i)
    cond = ctx.condOv.get(i, r.ex_op1(n))
    if cond is None or t is None:
        ctx.w(f"/* n{i}: {OPNAMES.get(op, op)} (cond/target unresolved) */")
        return i + 1
    # &&/|| short-circuit (JMPZ_EX/JMPNZ_EX)
    if op in (46, 47) and t > i + 1 and n.ent.get("op1") and (n.ent["op1"].kind & 6):
        slot = n.op1 // 16
        left = ctx.tempExpr.get(slot)
        if left is not None and _sc_pure_region(ctx, i + 1, t):
            emit_region(ctx, i + 1, t)  # temp defs only (guaranteed)
            if slot in ctx.tempExpr and ctx.tempExpr[slot] != left:
                ctx.tempExpr[slot] = "(" + unwrap(left) + " " + \
                    ("&&" if op == 46 else "||") + " " + unwrap(ctx.tempExpr[slot]) + ")"
                if i in ctx.jt and ctx.jt[i] > 0:
                    ctx.condOv[ctx.jt[i]] = ctx.tempExpr[slot]
                ctx.tempUses[slot] = [u for u in ctx.tempUses.get(slot, []) if u != i]
                ctx.bk(i)
                return t
    condTxt = unwrap(ctx.render.ch(cond))
    if op in (44, 47):
        condTxt = "!(" + condTxt + ")"
    isCase = False
    if n.ent.get("op1") and (n.ent["op1"].kind & 6):
        d = ctx.tempDef.get(n.op1 // 16)
        if d is not None and ctx.op[d] in (48, 194):
            isCase = True
    if t <= i + 1:  # backward/empty target: no if structure
        ctx.line(n)
        ctx.w(f"/* n{i}: {OPNAMES.get(op, op)} cond={condTxt} -> n{t} (loop back-edge) */")
        ctx.emitted += 1
        return i + 1
    # while-at-head: JMPZ at the head, body, then a JMP back to this node
    if t - 1 >= i + 1 and ctx.op[t - 1] == 42 and ctx.jt.get(t - 1) == i:
        ctx.line(n)
        ctx.w(f"while ({condTxt}) {{")
        ctx.idp += 1
        ctx.loop_stack.append(LoopInfo(frozenset({t}), frozenset({i})))
        emit_region(ctx, i + 1, t - 1)
        ctx.loop_stack.pop()
        ctx.idp -= 1
        ctx.w("}")
        ctx.emitted += 1
        return t
    # if / if-else
    hasElse = (not isCase and t - 1 >= i + 1 and ctx.op[t - 1] == 42
               and t - 1 in ctx.jt and ctx.jt[t - 1] > t and ctx.jt[t - 1] <= end)
    # (Part C) ternary: both arms are pure-def runs ending in a QM_ASSIGN
    # into the same temp slot (the JMPZ/QM_ASSIGN lowering — dawwinci
    # structurer.py:196-212; arms may be multi-node: `isset($a['k']) ?
    # $a['k'] : 25` lowers to FETCH_R+FETCH_DIM_R+QM_ASSIGN)
    if hasElse:
        skip = ctx.jt[t - 1]
        arms = _ternary_arms(ctx, i, t, skip)
        if arms is not None:
            slot, a, b = arms
            ctx.tempExpr[slot] = f"({condTxt} ? {a} : {b})"
            # the construct's effective def point is its END (the else
            # arm) so the single use inlines past the consumed JMP
            ctx.tempDef[slot] = t
            # accounting: the arm regions' defs are emitted (their
            # def_temp calls); the consumed branch head + exit JMP are
            # bookkeeping — the &&/|| merge's split
            ctx.bk(i)
            ctx.bk(t - 1)
            return skip
    ctx.line(n)
    ctx.w(f"if ({condTxt}) {{")
    cont = t
    ctx.idp += 1
    if hasElse:
        cont = ctx.jt[t - 1]  # node before target = then-exit JMP
        ctx.bk(t - 1)
        emit_region(ctx, i + 1, t - 1)
        ctx.idp -= 1
        ctx.w("} else {")
        ctx.idp += 1
        emit_region(ctx, t, cont)
    else:
        emit_region(ctx, i + 1, t)
    ctx.idp -= 1
    ctx.w("}")
    ctx.emitted += 1
    return cont


def emit_jmp_set(ctx: LiftContext, i: int, end: int) -> int:
    """`a ?: b` — the JMP_SET short-circuit (Part C; dawwinci
    structurer.py:379-396). The alternative region computes into the same
    res slot; the result temp carries the full elvis expression. Falls back
    to the pre-Part-C partial (op1 only) when the shape is unsupported."""
    from .emitter import emit_region

    n = ctx.nodes[i]
    r = ctx.render
    t = ctx.jt.get(i)
    e = n.ent.get("res")
    slot = n.res // 16 if e and (e.kind & 6) else None
    left = r.ex_op1(n)
    if t is None or t <= i or t > end or slot is None or left is None:
        return ctx.def_temp(n, r.ch(left), i)
    emit_region(ctx, i + 1, t)  # the alternative computation
    right = ctx.tempExpr.get(slot)
    if right is None and ctx.op[i + 1] == 31:
        ne = ctx.nodes[i + 1].ent.get("res")
        if ne and (ne.kind & 6):
            right = ctx.tempExpr.get(ctx.nodes[i + 1].res // 16)
    if right is None:
        right = "$T%d" % (slot - 5)
    ctx.tempExpr[slot] = f"({left} ?: {right})"
    ctx.emitted += 1
    return t


__all__ = ["emit_if", "emit_jmp", "emit_jmp_set", "emit_return", "emit_try",
           "loop_exit_stmt"]
