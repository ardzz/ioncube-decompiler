"""Control-flow shaping, part 1: try/catch, return, jumps (incl. the Part C
break/continue levels and the --valid-php goto-label fallback), if/else
with the &&/|| short-circuit merge and the Part C ternary folding. Loops
and switches live in loops.py / switches.py — emit_jmp delegates to them.
"""

from __future__ import annotations

from ..opcodes import OPNAMES
from .model import LoopInfo, LiftContext, _PLUMBING, _PURE
from .operand import bare, class_ref, prefix_operand, unwrap, zval_name

# the region between a short-circuit jump and its target must hold only
# these pure expression defs for the &&/|| merge to fire (emitIf's set,
# plus the FETCH family — a short-circuit's right term legally fetches:
# `$_SERVER['REQUEST_METHOD'] == 'POST' && empty($_POST)`)
_SC_PURE = (
    frozenset({0})
    | frozenset(range(1, 22))
    | {
        22,
        23,
        24,
        26,
        27,
        28,
        31,
        # array-literal pieces on the right of &&/||
        # (`in_array($x, [A, B])` in a condition)
        71,
        72,
        # PRE/POST INC/DEC: expression defs with a res temp
        # (`$str == "" && $count++ < 5`)
        34,
        35,
        36,
        37,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
        59,
        60,
        61,
        65,
        66,
        67,
        68,
        69,
        99,
        100,
        106,
        112,
        113,
        114,
        115,
        116,
        117,
        118,
        119,
        120,
        121,
        122,
        123,
        128,
        129,
        130,
        131,
        137,
        138,
        148,
        154,
        156,
        157,
        165,
        169,
        170,
        179,
        183,
        187,
        188,
        189,
        190,
        191,
        192,
    }
    | frozenset(range(80, 99))
    | frozenset(range(173, 179))
)


def _ternary_paren(e: str) -> str:
    """Parenthesize a nested ternary spliced into another ternary.

    PHP 8 rejects the old left-associative unparenthesized form
    (``a ? b : c ? d : e``); the extra parentheses keep the same parse.
    """
    return "(" + e + ")" if e and "?" in e else e


def _region_ends_terminal(ctx: LiftContext, lo: int, hi: int) -> bool:
    """True when the last real op of [lo, hi) always transfers control
    (RETURN / RETURN_BY_REF / EXIT / THROW / GENERATOR_RETURN, possibly
    behind a VERIFY_RETURN_TYPE).  Such a then-arm makes a statement-empty
    else-arm safe to drop: the else arm's value-only work is inlined at its
    later use, which only the fall-through path can reach."""
    for k in range(hi - 1, lo - 1, -1):
        op = ctx.op.get(k)
        if op in (62, 79, 108, 111, 161):
            return True
        if op == 42:  # JMP compiled to a shared RETURN epilogue
            t = ctx.jt.get(k)
            if t is not None and (
                ctx.op.get(t) in (62, 79, 108, 111, 161)
                or (
                    ctx.op.get(t) == 124
                    and ctx.op.get(t + 1) in (62, 111)
                )
            ):
                return True
            return False
        if op in (0, 70, 101, 124):  # NOP / FREE / EXT_STMT / verify
            continue
        return False
    return False


def _region_values_escape(ctx: LiftContext, lo: int, hi: int) -> bool:
    """True when a temp defined in [lo, hi) is read outside that region.
    A statement-empty else arm whose defs all stay inside it is pure dead
    work (e.g. a conditional jump to its own merge) and safe to drop."""
    for k in range(lo, hi):
        e = ctx.nodes[k].ent.get("res")
        if e is None or not (e.kind & 6):
            continue
        slot = e.raw // 16
        for u in ctx.tempUses.get(slot, []):
            if u < lo or u >= hi:
                return True
    return False


def _shared_tail_assign(
    ctx: LiftContext, i: int, t: int, cont: int, end: int
) -> int | None:
    """Recognise the encoder's conditional-assignment merge.

    Both arms compute the same temp V, the then arm additionally performs
    the target write as an assignment expression whose result feeds V, and
    a single ASSIGN_DIM/OBJ + OP_DATA at the else-fallthrough point repeats
    the write.  Leaving that merge after the if repeats the write on the
    then path (a recovered method produced `1/Call/Call` instead of
    `1/Call`).  Returning cont+2 pulls the merge write into the else arm,
    where the then arm's own assignment already made it redundant.

    Conservative: requires the then arm to carry an assignment with the
    same rendered lvalue as the merge, linked to the merge's OP_DATA temp
    through a QM_ASSIGN, and the else arm to define that temp itself.
    Returns None otherwise (generic shape kept)."""
    if cont + 1 >= end:
        return None
    m = ctx.nodes[cont]
    if ctx.op.get(cont) not in (23, 24) or ctx.op.get(cont + 1) != 137:
        return None
    ve = ctx.nodes[cont + 1].ent.get("op1")
    if ve is None or not (ve.kind & 6):
        return None
    vslot = ve.raw // 16
    mop1 = ctx.render.ex_op1(m)
    mop2 = ctx.render.ex_op2(m)
    thenAssign = None
    for k in range(t - 2, i, -1):  # then arm [i+1, t-1)
        nk = ctx.nodes[k]
        if ctx.op.get(k) not in (23, 24):
            continue
        if ctx.render.ex_op1(nk) == mop1 and ctx.render.ex_op2(nk) == mop2:
            thenAssign = k
            break
    if thenAssign is None:
        return None
    re_ = ctx.nodes[thenAssign].ent.get("res")
    if re_ is None or not (re_.kind & 6):
        return None
    aslot = re_.raw // 16
    linked = False
    for k in range(thenAssign + 1, t - 1):
        nk = ctx.nodes[k]
        if ctx.op.get(k) != 31:  # QM_ASSIGN
            continue
        r2 = nk.ent.get("res")
        o2 = nk.ent.get("op1")
        if (
            r2 is not None
            and (r2.kind & 6)
            and r2.raw // 16 == vslot
            and o2 is not None
            and (o2.kind & 6)
            and o2.raw // 16 == aslot
        ):
            linked = True
            break
    if not linked:
        return None
    for k in range(t, cont):
        r2 = ctx.nodes[k].ent.get("res")
        if r2 is not None and (r2.kind & 6) and r2.raw // 16 == vslot:
            return cont + 2
    return None


def loop_exit_stmt(ctx: LiftContext, target: int) -> str | None:
    """break;/continue; with level."""
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
    # the class operand is a NAME, not a string literal: the zval form escapes
    # backslashes (`Vendor\\Client`), so resolve it like INSTANCEOF does and
    # only fall back to the rendered (quote-stripped) form.
    ce = catchN.ent.get("op1")
    cls = None
    if ce is not None and ce.kind == 1 and ce.raw < len(ctx.zvals):
        cls = zval_name(ctx.zvals[ce.raw])
    if cls is None:
        cls = bare(ctx.render.ch(ctx.render.ex_op1(catchN)))
    cls = class_ref(cls)
    e = catchN.ent.get("res")
    var = ctx.cv_name(e.raw) if e and e.kind == 8 else "$e"
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
    if isNull:
        # a typed function's bare `return;` is a compile error
        # (`A method with return type must return a value`)
        ctx.w("return null;" if ctx.meta.get("hasRetType") else "return;")
    else:
        ctx.w("return " + unwrap(ctx.render.ch(v)) + ";")
    ctx.emitted += 1
    return i + 1


def emit_jmp(ctx: LiftContext, i: int, end: int) -> int:
    from . import loops

    n = ctx.nodes[i]
    t = ctx.jt.get(i)
    if t is None:
        ctx.w(f"/* n{i}: JMP (unresolved target) */")
        return i + 1
    # (Part C) break/continue against the loop/switch stack — an explicit
    # structured target wins over the jump-to-return shape (a match arm's
    # terminal JMP targets the merge RETURN: it is the arm's break)
    stmt = loop_exit_stmt(ctx, t)
    if stmt is not None:
        ctx.line(n)
        ctx.w(stmt)
        ctx.emitted += 1
        return i + 1
    if ctx.op[t] == 62:  # mid-function return compiled as JMP
        return _jmp_return(ctx, i, t, t, end, f" -> n{t}")
    if ctx.op[t] == 124 and ctx.op.get(t + 1) == 62:  # VERIFY+RETURN epilogue
        return _jmp_return(ctx, i, t + 1, t, end, f" -> epilogue n{t}")
    if t > i and t <= end + 1:
        # bottom-tested while (with priming) — the generalization of the
        # old loop-entry form; loops.py owns it
        bt = loops.bottom_tested_while(ctx, i, t, end)
        if bt is not None:
            return bt
    if t < i:
        if ctx.debug:
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
    if ctx.debug:
        ctx.w(f"/* n{i}: JMP -> n{t} */")
    return i + 1


def _jmp_return(
    ctx: LiftContext, i: int, tnode: int, ret: int, end: int, tag: str
) -> int:
    n = ctx.nodes[i]
    tn = ctx.nodes[tnode]
    v = ctx.render.ex_op1(tn)
    isNull = v is None or v == "null"
    # the unreachable epilogue after an inlined `return X;` duplicates the
    # return — skip it so a typed function keeps a single return path
    prev = next((ln.strip() for ln in reversed(ctx.out) if ln.strip()), "")
    if isNull and prev.startswith("return"):
        return ret if ret < end else end
    ctx.line(n)
    if isNull:
        # a typed function's bare `return;` is a compile error
        body = "return null;" if ctx.meta.get("hasRetType") else "return;"
        ctx.w(f"{body} /*{tag} */")
    else:
        ctx.w(f"return {unwrap(ctx.render.ch(v))}; /*{tag} */")
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
    ln = ctx.nodes[hi - 1]
    le = ln.ent.get("res")
    if not le or not (le.kind & 6):
        return None
    if ctx.op[hi - 1] == 31:
        pass  # QM_ASSIGN arm
    elif ctx.op[hi - 1] == 149:
        pass  # HANDLE_EXCEPTION carrying the arm value
    else:
        return None
    for k in range(lo, hi):
        o = ctx.op[k]
        if o in _PLUMBING or o == 100:
            continue
        if o in (42, 43, 44, 46, 47, 152):
            # a branch folded into an expression operand (the else arm's
            # own short-circuit / nested ternary / `?:`, `empty($m) ? 0 :
            # (a || b ? 2 : 1)`); its target must stay inside the arm or
            # land on the arm's merge
            m = ctx.jt.get(k)
            if m is None or not (lo < m <= hi):
                return None
            continue
        ne = ctx.nodes[k].ent.get("res")
        if o not in _PURE or not ne or not (ne.kind & 6):
            return None
    return ln.res // 16


def _ternary_arms(
    ctx: LiftContext, i: int, t: int, skip: int
) -> tuple[int, str, str] | None:
    """The then arm [i+1, t-1) and else arm [t, skip) of a JMPZ shape, when
    both end in a QM_ASSIGN into the same result slot and nothing reads
    that slot before ``skip``: emit both arm regions (expression defs only)
    and return (slot, then_expr, else_expr). None when the shape does not
    hold."""
    from .emitter import emit_region

    if t <= i + 1 or skip <= t:
        return None
    slot = _pure_arm(ctx, i + 1, t - 1)
    if slot is None:
        return None
    elseSlot = _pure_arm(ctx, t, skip)
    if elseSlot == slot:
        emit_region(ctx, t, skip)
        b = ctx.tempExpr.get(slot)
    else:
        # the else arm is itself a nested ternary ([cmp][JMPZ][QM][JMP]
        # ...): fold it first; its output slot feeds this level's result
        if (
            elseSlot is not None
            or ctx.op[t + 1] not in (43, 44)
            or ctx.op[t + 2] != 31
            or ctx.op[t + 3] != 42
        ):
            return None
        m = _ternary_chain(ctx, t + 1, skip)
        if m is None:
            return None
        b = ctx.tempExpr.get(m[0])
        if b is None:
            return None
    if any(u < skip for u in ctx.tempUses.get(slot, [])):
        return None  # an inner read: the slot is not the ternary result
    emit_region(ctx, i + 1, t - 1)
    a = ctx.tempExpr.get(slot)
    if a is None or b is None:
        return None
    return slot, a, b


def _ternary_chain(ctx: LiftContext, i: int, end: int) -> tuple[int, int] | None:
    """The nested ternary lowering (`a ? b : c ? d : e`): a JMPZ chain whose
    each level is [cond-def][JMPZ -> next][QM value][JMP -> merge], the last
    level's else is a bare QM_ASSIGN, and a run of QM_ASSIGN(T -> T) linker
    copies lifts the result up to the slot the outside ASSIGN reads. Renders
    as one ternary expression into the output slot's tempExpr and books the
    whole span. None when the shape does not hold."""
    from .emitter import emit_node

    r = ctx.render

    def arm_txt(k: int) -> str | None:
        q = ctx.nodes[k]
        v = r.ex_op1(q)
        return r.ch(v) if v is not None else None

    def cond_txt(h: int) -> str | None:
        # the level's condition def ([h-1] cmp) may not be walked yet when
        # this chain runs nested inside another fold — render it now
        cslot = ctx.nodes[h].op1 // 16
        if (
            ctx.tempExpr.get(cslot) is None
            and h - 1 >= 0
            and ctx.tempDef.get(cslot) == h - 1
        ):
            emit_node(ctx, h - 1, h)
        txt = unwrap(r.ch(ctx.condOv.get(h, r.ex_op1(ctx.nodes[h]))))
        if txt is None:
            return None
        if ctx.op[h] == 44:
            txt = "!" + prefix_operand(txt)
        return txt

    # level 1 shape: [JMPZ at i][QM at i+1][JMP at i+2]
    if not (ctx.op[i + 1] == 31 and ctx.op[i + 2] == 42):
        return None
    condTxt = cond_txt(i)
    if condTxt is None:
        return None
    levels = []
    j = i
    while True:
        t = ctx.jt.get(j)
        if t is None or not (ctx.op[j + 1] == 31 and ctx.op[j + 2] == 42):
            return None
        q = ctx.nodes[j + 1]
        qe = q.ent.get("res")
        if not qe or not (qe.kind & 6):
            return None
        v = arm_txt(j + 1)
        if v is None:
            return None
        levels.append((condTxt, v))
        nxt = ctx.nodes[j].ent.get("op2")
        if nxt is None or nxt.kind != 0:
            return None
        n = nxt.raw - 1
        if not (i < n < ctx.thr):
            return None
        if ctx.op[n + 1] in (43, 44) and ctx.op[n + 2] == 31 and ctx.op[n + 3] == 42:
            # another ternary level: [cmp][JMPZ][QM][JMP] — its JMPZ is
            # the else arm's head
            condTxt = cond_txt(n + 1)
            if condTxt is None:
                return None
            j = n + 1
            continue
        break
    # the else arm: a bare QM_ASSIGN at n (its value or a temp read)
    elseStart = n
    elseQ = ctx.nodes[elseStart]
    elseE = elseQ.ent.get("res")
    if not elseE or not (elseE.kind & 6) or ctx.op[elseStart] != 31:
        return None
    b = arm_txt(elseStart)
    if b is None:
        return None
    # the linker run: QM_ASSIGN(T_prev -> T_new) lifting the result up.
    # Slots are the node's conv values (tempExpr is conv-keyed); the ent
    # raws only verify the T-to-T operand shape.
    k = elseStart + 1
    outSlot = elseQ.res // 16
    linkers = []
    while k < ctx.thr and ctx.op[k] == 31:
        lk = ctx.nodes[k]
        lo1 = lk.ent.get("op1")
        if not lo1 or not (lo1.kind & 2) or lk.op1 // 16 != outSlot:
            break
        outSlot = lk.res // 16
        linkers.append(k)
        k += 1
    if not linkers:
        return None
    expr = b
    for condTxt, v in reversed(levels):
        expr = (
            f"({_ternary_paren(condTxt)} ? {_ternary_paren(v)} : "
            f"{_ternary_paren(expr)})"
        )
    # the whole span is consumed; the result lives in the linker output slot
    ctx.tempExpr[outSlot] = expr
    ctx.tempDef[outSlot] = k - 1
    ctx.tempUses[outSlot] = [u for u in ctx.tempUses.get(outSlot, []) if u >= k]
    ctx.line(ctx.nodes[i])
    ctx.emitted += 1
    for k2 in range(i, k):
        ctx.bk(k2)
    return outSlot, k


def _pure_region(ctx: LiftContext, lo: int, hi: int) -> bool:
    """[lo, hi) holds only pure expression defs (no statements)."""
    for k in range(lo, hi):
        o = ctx.op[k]
        if o in _PLUMBING:
            continue
        ne = ctx.nodes[k].ent.get("res")
        if o not in _PURE or not ne or not (ne.kind & 6):
            return False
    return True


def _ternary_plan(
    ctx: LiftContext, j: int, limit: int, cond_start: int | None = None
) -> tuple[int, dict] | None:
    """Plan a QM_ASSIGN ternary, including the 0044b/00442 shapes where the
    condition is a multi-node `isset($a['k'])` def and the then-arm is a
    multi-node fetch.  Validation only; :func:`_ternary_exec` emits."""
    t = ctx.jt.get(j)
    if t is None or t <= j + 1 or t >= limit:
        return None
    if cond_start is not None:
        if cond_start >= j or not _pure_region(ctx, cond_start, j):
            return None
    if ctx.op[t - 1] != 42:
        return None
    merge = ctx.jt.get(t - 1)
    if merge is None or merge <= t or merge > limit:
        return None
    slot = _pure_arm(ctx, j + 1, t - 1)
    truePlan = None
    if slot is None:
        # nested ternary in the then-arm: [cond defs][JMPZ ...][linkers]
        ts, te = j + 1, t - 1
        for k in range(ts, te):
            if ctx.op.get(k) not in (43, 44):
                continue
            if not _pure_region(ctx, ts, k):
                continue
            # a direct CV/temp condition has no def run before the JMPZ:
            # cond_start must not reach the branch node itself
            inner = _ternary_plan(
                ctx, k, te, cond_start=ts if k > ts else None
            )
            if inner is None:
                continue
            islot, iplan = inner
            cur = islot
            kk = iplan["merge"]
            ok = True
            while kk < te:
                q = ctx.nodes[kk]
                e = q.ent.get("op1")
                res = q.ent.get("res")
                if (
                    ctx.op.get(kk) != 31
                    or e is None
                    or res is None
                    or not (res.kind & 6)
                    or (q.op1 // 16) != cur
                ):
                    ok = False
                    break
                cur = q.res // 16
                kk += 1
            if ok and kk == te:
                slot = cur
                truePlan = inner[1]
                break
    if slot is None:
        return None
    if any(u < merge for u in ctx.tempUses.get(slot, [])):
        return None
    false = None
    for k in range(t, merge):
        if ctx.op[k] not in (43, 44) or ctx.jt.get(k) is None:
            continue
        if not _pure_region(ctx, t, k):
            continue
        inner = _ternary_plan(
            ctx, k, merge, cond_start=t if k > t else None
        )
        if inner is None:
            continue
        islot, iplan = inner
        cur = islot
        kk = iplan["merge"]
        ok = True
        while kk < merge:
            q = ctx.nodes[kk]
            e = q.ent.get("op1")
            res = q.ent.get("res")
            if (
                ctx.op[kk] != 31
                or e is None
                or res is None
                or not (res.kind & 6)
                or (q.op1 // 16) != cur
            ):
                ok = False
                break
            cur = q.res // 16
            kk += 1
        if ok and kk == merge and cur == slot:
            false = ("nested", inner)
            break
    if false is None:
        fslot = _pure_arm(ctx, t, merge)
        if fslot != slot:
            return None
        false = ("arm",)
    return slot, {
        "j": j,
        "cond_start": cond_start,
        "t": t,
        "merge": merge,
        "true": (j + 1, t - 1, slot),
        "true_plan": truePlan,
        "false": false,
    }


def _ternary_exec(ctx: LiftContext, plan: dict) -> tuple[int, int] | None:
    from .emitter import emit_region

    j = plan["j"]
    t = plan["t"]
    merge = plan["merge"]
    slot = plan["true"][2]
    if plan["cond_start"] is not None:
        emit_region(ctx, plan["cond_start"], j)
    cond = unwrap(
        ctx.render.ch(ctx.condOv.get(j, ctx.render.ex_op1(ctx.nodes[j])))
    )
    if cond is None:
        return None
    if ctx.op[j] in (44, 47):
        cond = "!" + prefix_operand(cond)
    ts, te, _ = plan["true"]
    if plan.get("true_plan") is not None:
        m = _ternary_exec(ctx, plan["true_plan"])
        if m is None:
            return None
        _islot, iend = m
        emit_region(ctx, iend, te)
    else:
        emit_region(ctx, ts, te)
    a = ctx.tempExpr.get(slot)
    false = plan["false"]
    if false[0] == "nested":
        iplan = false[1][1]
        m = _ternary_exec(ctx, iplan)
        if m is None:
            return None
        islot, iend = m
        b = ctx.tempExpr.get(islot)
        emit_region(ctx, iend, merge)
        if slot not in ctx.tempExpr:
            ctx.tempExpr[slot] = b
    else:
        emit_region(ctx, t, merge)
        b = ctx.tempExpr.get(slot)
    if a is None or b is None:
        return None
    ctx.tempExpr[slot] = (
        f"({_ternary_paren(cond)} ? {_ternary_paren(a)} : "
        f"{_ternary_paren(b)})"
    )
    ctx.tempDef[slot] = merge - 1
    ctx.tempUses[slot] = [u for u in ctx.tempUses.get(slot, []) if u >= merge]
    for kk in range(j, merge):
        ctx.bk(kk)
    return slot, merge


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
        if o in (42, 43, 44):
            # a branch that stays inside the operand region: the ternary /
            # QM lowering of the right term (`empty($x) && (is_countable($x)
            # ? count($x) : 0)`); the folder renders it into one expression
            m = ctx.jt.get(k)
            if m is None or not (lo < m <= hi):
                return False
            k += 1
            continue
        ne = ctx.nodes[k].ent.get("res")
        if not ne or not (ne.kind & 6) or o not in _SC_PURE:
            return False
        k += 1
    return True


def _sc_chain_plan(ctx: LiftContext, i: int, t: int, end: int) -> dict | None:
    """Recognise a swapped-layout `if (A && B && C) { then } else { else }`.

    The encoder sometimes emits the false arm before the true arm:

        JMPZ A -> false          (the outer branch at i)
        <eval B>; JMPZ B -> false
        <eval C>; JMPZ C -> false
        JMP -> true_body          (at t-1)
        false_body ... JMP -> merge
        true_body  ... JMP -> merge

    Rendering that as nested ifs leaves the true body after the else and
    runs the false-path return unconditionally (the recovered method
    returned "invalid URI" for every destination).  The
    plain JMPZ chain is AND: any false jumps to the false arm, all true
    fall through the tail JMP into the true arm."""
    if ctx.op.get(i) != 43 or ctx.op.get(t - 1) != 42:
        return None
    skip = ctx.jt.get(t - 1)
    if skip is None or skip <= t or skip > end:
        return None
    chain = [i]
    k = i
    for j in range(i + 1, t - 1):
        if ctx.op.get(j) not in (43, 44):
            continue
        if ctx.op.get(j) != 43 or ctx.jt.get(j) != t:
            return None
        if not _sc_pure_region(ctx, k + 1, j):
            return None
        chain.append(j)
        k = j
    if not _sc_pure_region(ctx, k + 1, t - 1):
        return None
    # the false arm ends with its merge JMP right before the true body
    if skip - 1 < t or ctx.op.get(skip - 1) != 42:
        return None
    mj = ctx.jt.get(skip - 1)
    if mj is None or mj <= skip or mj > end:
        return None
    # the true arm ends with a JMP to the same merge
    tJ = None
    for j in range(skip, mj):
        if ctx.op.get(j) == 42 and ctx.jt.get(j) == mj:
            tJ = j
            break
    if tJ is None:
        return None
    merge = ctx.jt.get(mj) if ctx.op.get(mj) == 42 else mj
    if merge is None or merge <= mj or merge > end:
        return None
    return {
        "i": i,
        "t": t,
        "skip": skip,
        "chain": chain,
        "fJ": skip - 1,
        "tJ": tJ,
        "mj": mj,
        "merge": merge,
    }


def _sc_chain_cond(ctx: LiftContext, k: int) -> str | None:
    n = ctx.nodes[k]
    e = n.ent.get("op1")
    if e is not None and (e.kind & 6):
        txt = ctx.tempExpr.get(n.op1 // 16)
        if txt is not None:
            return unwrap(txt)
    return unwrap(ctx.render.ch(ctx.render.ex_op1(n)))


def _emit_sc_chain(ctx: LiftContext, plan: dict) -> int | None:
    from .emitter import emit_region

    i = plan["i"]
    t = plan["t"]
    skip = plan["skip"]
    chain = plan["chain"]
    conds = []
    prev = i
    for k in chain:
        if k == i:
            c = _sc_chain_cond(ctx, k)
        else:
            emit_region(ctx, prev + 1, k)  # operand evaluation only
            c = _sc_chain_cond(ctx, k)
        if c is None:
            return None
        conds.append(c)
        prev = k
    emit_region(ctx, prev + 1, t - 1)  # trailing operand glue, no tail JMP
    ctx.line(ctx.nodes[i])
    ctx.w("if (" + " && ".join(conds) + ") {")
    ctx.idp += 1
    emit_region(ctx, skip, plan["tJ"])
    ctx.idp -= 1
    ctx.w("} else {")
    ctx.idp += 1
    emit_region(ctx, t, plan["fJ"])
    ctx.idp -= 1
    ctx.w("}")
    ctx.emitted += 1
    for k in (i, t - 1, plan["fJ"], plan["tJ"], plan["mj"], *chain):
        ctx.bk(k)
    return plan["merge"]


def _elseif_cond(ctx: LiftContext, k: int) -> str | None:
    c = ctx.condOv.get(k)
    if c is not None:
        return unwrap(ctx.render.ch(c))
    n = ctx.nodes[k]
    e = n.ent.get("op1")
    if e is not None and (e.kind & 6):
        slot = n.op1 // 16
        es = ctx.effSlot.get(f"{k}:op1")
        if es is not None:
            slot = es
        txt = ctx.tempExpr.get(slot)
        if txt is not None:
            return unwrap(txt)
    return unwrap(ctx.render.ch(ctx.render.ex_op1(n)))


def _elseif_chain_plan(ctx: LiftContext, i: int, end: int) -> dict | None:
    """The encoder's `if/elseif/.../else` lowering.

    A run of JMPNZ tests is followed by their true bodies packed after the
    test region; each body ends in a JMP to one merge, and a trailing JMP
    before the bodies targets the else body.  Reading this as nested
    if/else pools every body into one arm (callerid_get_config's
    is_string/strtolower/ctype_digit chain appended RAND(2,9),
    RAND(0,9), RAND(1,9) and the CUT in a single else).
    """
    if ctx.op.get(i) != 44:
        return None
    t = ctx.jt.get(i)
    if t is None or t <= i + 2 or t >= end:
        return None
    if ctx.op.get(t - 1) != 42:
        return None
    E = ctx.jt.get(t - 1)
    if E is None or E <= t or E >= end:
        return None
    tests = [i]
    for j in range(i + 1, t - 1):
        o = ctx.op.get(j)
        if o == 44:
            bj = ctx.jt.get(j)
            if bj is None or bj <= t:
                return None
            tests.append(j)
        elif o in (43, 46, 47):
            continue
        elif o == 42:
            return None
    bodies = [t] + [ctx.jt[j] for j in tests[1:]]
    if len(tests) < 2:
        return None
    if any(b2 <= b1 for b1, b2 in zip(bodies, bodies[1:])):
        return None
    if bodies[-1] >= E:
        return None
    bounds = bodies[1:] + [E]
    merge = None
    exits = []
    for b, hi in zip(bodies, bounds):
        q = hi - 1
        if q <= b or ctx.op.get(q) != 42:
            return None
        mj = ctx.jt.get(q)
        if mj is None or mj <= E or mj > end:
            return None
        if merge is None:
            merge = mj
        elif mj != merge:
            return None
        exits.append(q)
    # the else arm ends with a JMP to the same merge
    q = merge - 1
    if q <= E or ctx.op.get(q) != 42 or ctx.jt.get(q) != merge:
        return None
    exits.append(q)
    return {
        "i": i,
        "t": t,
        "E": E,
        "tests": tests,
        "bodies": bodies,
        "bounds": bounds,
        "exits": exits,
        "merge": merge,
        "end": end,
    }


def _emit_elseif_chain(ctx: LiftContext, plan: dict) -> int | None:
    from .emitter import emit_node, emit_region

    i = plan["i"]
    tests = plan["tests"]
    bodies = plan["bodies"]
    bounds = plan["bounds"]
    conds = [_elseif_cond(ctx, i)]
    if conds[0] is None:
        return None
    prev = i
    for k in tests[1:]:
        h = None
        for x in range(prev + 1, k):
            if ctx.op.get(x) in (46, 47):
                h = x
                break
        if h is not None:
            ht = ctx.jt.get(h)
            if ht is None or not _sc_pure_region(ctx, h + 1, ht):
                return None
            emit_region(ctx, prev + 1, h)
            emit_node(ctx, h, plan["end"])
        else:
            emit_region(ctx, prev + 1, k)
        c = _elseif_cond(ctx, k)
        if c is None:
            return None
        conds.append(c)
        prev = k
    emit_region(ctx, prev + 1, plan["t"] - 1)
    ctx.line(ctx.nodes[i])
    for idx, b in enumerate(bodies):
        if idx == 0:
            ctx.w("if (" + conds[idx] + ") {")
        else:
            ctx.w("} elseif (" + conds[idx] + ") {")
        ctx.idp += 1
        emit_region(ctx, b, bounds[idx] - 1)
        ctx.idp -= 1
        ctx.bk(bounds[idx] - 1)
    ctx.w("} else {")
    ctx.idp += 1
    emit_region(ctx, plan["E"], plan["merge"] - 1)
    ctx.idp -= 1
    ctx.bk(plan["merge"] - 1)
    ctx.w("}")
    ctx.emitted += 1
    for k in tests:
        ctx.bk(k)
    ctx.bk(plan["t"] - 1)
    return plan["merge"]


def emit_if(ctx: LiftContext, i: int, end: int, op: int) -> int:
    from .emitter import emit_region

    n = ctx.nodes[i]
    r = ctx.render
    t = ctx.jt.get(i)
    cond = ctx.condOv.get(i, r.ex_op1(n))
    if cond is None or t is None:
        ctx.w(f"/* n{i}: {OPNAMES.get(op, op)} (cond/target unresolved) */")
        return i + 1
    # if/elseif/else chain: JMPNZ tests with their true bodies pooled after
    # the test region (callerid_get_config's is_string/strtolower chain)
    if op == 44 and t > i + 2:
        plan = _elseif_chain_plan(ctx, i, end)
        if plan is not None:
            m = _emit_elseif_chain(ctx, plan)
            if m is not None:
                return m
    # swapped-layout `if (A && B && C) { then } else { else }` (the true
    # arm sits after the false arm; plain JMPZ chain)
    if op == 43 and t > i + 2:
        plan = _sc_chain_plan(ctx, i, t, end)
        if plan is not None:
            m = _emit_sc_chain(ctx, plan)
            if m is not None:
                return m
    # &&/|| short-circuit (JMPZ_EX/JMPNZ_EX)
    if op in (46, 47) and t > i + 1 and n.ent.get("op1"):
        e1 = n.ent["op1"]
        slot = None
        left = None
        if e1.kind & 6:
            slot = n.op1 // 16
            left = ctx.tempExpr.get(slot)
        if left is None:
            # a CV/constant left operand (`$force || ...`): the expression
            # is already available; only temp operands need def tracking
            left = unwrap(ctx.render.ch(ctx.render.ex_op1(n)))
        # The branch's result temp may be a different slot than its input
        # (JMPNZ_EX V251 -> T252): the OR/AND value is in n.res, and the
        # right operand writes that slot, not the input.
        re_ = n.ent.get("res")
        res_slot = n.res // 16 if re_ is not None and (re_.kind & 6) else slot
        if left is not None and res_slot is not None and _sc_pure_region(
            ctx, i + 1, t
        ):
            # The chain writes the same condition temp at every level; its
            # registered uses are all the JMPZ_EX nodes.  While rendering
            # the right operand, expose only the next consumer (t) so the
            # temp defs inline instead of staging `$T = ...` statements.
            saved = ctx.tempUses.get(slot, []) if slot is not None else []
            saved_res = ctx.tempUses.get(res_slot, []) if res_slot != slot else saved
            saved_expr_assign = ctx.meta.get("exprAssign")
            if slot is not None:
                ctx.tempUses[slot] = [t]
            if res_slot != slot:
                ctx.tempUses[res_slot] = [t]
            ctx.meta["exprAssign"] = True
            try:
                emit_region(ctx, i + 1, t)  # temp defs only (guaranteed)
            finally:
                if saved_expr_assign is None:
                    ctx.meta.pop("exprAssign", None)
                else:
                    ctx.meta["exprAssign"] = saved_expr_assign
                if slot is not None:
                    ctx.tempUses[slot] = [u for u in saved if u != i]
                if res_slot != slot:
                    ctx.tempUses[res_slot] = [u for u in saved_res if u != i]
            right = ctx.tempExpr.get(res_slot)
            if right is not None and right != left:
                expr = (
                    "("
                    + unwrap(left)
                    + " "
                    + ("&&" if op == 46 else "||")
                    + " "
                    + unwrap(right)
                    + ")"
                )
                ctx.tempExpr[res_slot] = expr
                ctx.tempDef[res_slot] = i
                if i in ctx.jt and ctx.jt[i] > 0:
                    ctx.condOv[ctx.jt[i]] = expr
                ctx.tempUses[res_slot] = [
                    u for u in ctx.tempUses.get(res_slot, []) if u != i
                ]
                if slot is not None and slot != res_slot:
                    ctx.tempUses[slot] = [
                        u for u in ctx.tempUses.get(slot, []) if u != i
                    ]
                ctx.bk(i)
                return t
    condTxt = unwrap(ctx.render.ch(cond))
    if op in (44, 47):
        condTxt = "!" + prefix_operand(condTxt)
    isCase = False
    if n.ent.get("op1") and (n.ent["op1"].kind & 6):
        d = ctx.tempDef.get(n.op1 // 16)
        if d is not None and ctx.op[d] in (48, 194):
            isCase = True
    if op == 43 and t == i + 1 and end > i + 1:
        # A terminal guard: the encoder stores "the next instruction" as a
        # JMPZ target when the false path exits the enclosing region, so the
        # rest of the region is the then-body (an installer's swap-warning
        # guard, a licensed module's constructor guards).
        # A real forward target would name the join instead.
        ctx.line(n)
        ctx.w(f"if ({condTxt}) {{")
        ctx.idp += 1
        emit_region(ctx, i + 1, end)
        ctx.idp -= 1
        ctx.w("}")
        ctx.emitted += 1
        return end
    if t <= i + 1:  # backward/empty target: no if structure
        ctx.line(n)
        if ctx.debug:
            # cond text can embed `*/` (a regex literal like `(.*);*/`) —
            # escape it so the comment can't terminate early
            ctx.w(
                f"/* n{i}: {OPNAMES.get(op, op)} cond={condTxt.replace('*/', '* /')} -> n{t} (loop back-edge) */"
            )
            ctx.emitted += 1
        return i + 1
    # a guard whose then arm is a single loop-exit JMP: `if (cond) continue;`
    if (
        i + 1 == t - 1
        and ctx.op[t - 1] == 42
        and t - 1 in ctx.jt
    ):
        stmt = loop_exit_stmt(ctx, ctx.jt[t - 1])
        if stmt is None and ctx.loop_stack and ctx.jt[t - 1] <= i:
            stmt = "continue;"  # backward JMP to the loop head
        if stmt is not None:
            ctx.line(n)
            ctx.w(f"if ({condTxt}) {{ {stmt} }}")
            ctx.bk(t - 1)
            ctx.emitted += 1
            return t
    # empty then with a garbled else-entry JMP (an empty-then guard:
    # `if (!$flag) {} else { $obj->splice(...); }`).  The JMP right
    # after the JMPZ carries the JMPZ's target instead of the merge; the
    # else arm is the straight-line region starting at t and ending at the
    # first forward JMP.
    if (
        op == 43
        and i + 1 == t - 1
        and ctx.op.get(t - 1) == 42
        and ctx.jt.get(t - 1) == t
        and t < end
    ):
        fJ = None
        for j in range(t, end):
            o = ctx.op.get(j)
            if o in (77, 125) or o in (43, 44, 46, 47):
                break  # the arm has its own control flow: leave generic
            if o == 42:
                mj = ctx.jt.get(j)
                if mj is not None and mj > j:
                    fJ = j
                break
        if fJ is not None:
            ctx.line(n)
            ctx.w(f"if ({condTxt}) {{")
            ctx.w("} else {")
            ctx.idp += 1
            emit_region(ctx, t, fJ)
            ctx.idp -= 1
            ctx.w("}")
            ctx.bk(i)
            ctx.bk(t - 1)
            ctx.bk(fJ)
            ctx.emitted += 1
            merge = ctx.jt.get(fJ)
            if ctx.op.get(merge) == 42:
                ctx.bk(merge)
                m2 = ctx.jt.get(merge)
                if m2 is not None and m2 > merge:
                    merge = m2
            return merge
        # A non-straight-line else arm (the foreach in
        # callerid_get_config).  The empty-then exit JMP's operand is
        # garbled to the JMPZ target; when the if/else fills the rest of
        # the enclosing region — its tail is the region's exit JMP or a
        # terminator — that tail is the true merge: render the remainder
        # as the else body and let the caller emit the tail (the case
        # break/return).
        tail = end - 1
        tail_ok = False
        if tail > t:
            tail_op = ctx.op.get(tail)
            if tail_op == 42:
                mj = ctx.jt.get(tail)
                tail_ok = mj is not None and mj >= end
            elif tail_op in (62, 79, 108):
                tail_ok = True
        if tail_ok:
            ctx.line(n)
            ctx.w(f"if ({condTxt}) {{")
            ctx.w("} else {")
            ctx.idp += 1
            emit_region(ctx, t, tail)
            ctx.idp -= 1
            ctx.w("}")
            ctx.bk(i)
            ctx.bk(t - 1)
            ctx.emitted += 1
            return tail
    # a degenerate then-arm JMP outside a straight-line else: the encoder
    # garbled its operand to the JMPZ target (a loop guard `if ($found)
    # { break; }`).  Only the innermost real loop (continue target set)
    # qualifies — a switch's LoopInfo has no continue targets, and
    # breaking it could skip statements the empty then-arm must fall
    # through to.
    if (
        i + 1 == t - 1
        and ctx.op.get(t - 1) == 42
        and ctx.jt.get(t - 1) == t
        and ctx.loop_stack
    ):
        loop = ctx.loop_stack[-1]
        if loop.continue_targets and any(b > t for b in loop.break_targets):
            ctx.line(n)
            ctx.w(f"if ({condTxt}) {{ break; }}")
            ctx.bk(t - 1)
            ctx.emitted += 1
            return t
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
    hasElse = (
        not isCase
        and t - 1 >= i + 1
        and ctx.op[t - 1] == 42
        and t - 1 in ctx.jt
        and ctx.jt[t - 1] > t
        and ctx.jt[t - 1] <= end
    )
    if hasElse:
        skip = ctx.jt[t - 1]
        # terminal if/else placed then-after-else: the then body is empty
        # and the false-arm JMP lands directly on the then block (usually a
        # RETURN); the generic shape would leave the then body after the if
        if i + 1 == t - 1 and ctx.op.get(skip) in (62, 108, 79):
            ctx.line(n)
            ctx.w(f"if ({condTxt}) {{")
            ctx.idp += 1
            emit_region(ctx, skip, skip + 1)
            ctx.idp -= 1
            ctx.w("} else {")
            ctx.idp += 1
            emit_region(ctx, t, skip)
            ctx.idp -= 1
            ctx.w("}")
            ctx.emitted += 1
            ctx.bk(t - 1)
            return skip + 1
    # (Part C) ternary: both arms are pure-def runs ending in a QM_ASSIGN
    # into the same temp slot (the JMPZ/QM_ASSIGN lowering; arms may be
    # multi-node: `isset($a['k']) ?
    # $a['k'] : 25` lowers to FETCH_R+FETCH_DIM_R+QM_ASSIGN)
    if hasElse:
        skip = ctx.jt[t - 1]
        arms = _ternary_arms(ctx, i, t, skip)
        if arms is not None:
            slot, a, b = arms
            ctx.tempExpr[slot] = (
                f"({_ternary_paren(condTxt)} ? {_ternary_paren(a)} : "
                f"{_ternary_paren(b)})"
            )
            # the construct's effective def point is its END (the else
            # arm) so the single use inlines past the consumed JMP
            ctx.tempDef[slot] = skip - 1
            # accounting: the arm regions' defs are emitted (their
            # def_temp calls); the consumed branch head + exit JMP are
            # bookkeeping — the &&/|| merge's split
            ctx.bk(i)
            ctx.bk(t - 1)
            return skip
        tp = _ternary_plan(ctx, i, end)
        if tp is not None:
            m = _ternary_exec(ctx, tp[1])
            if m is not None:
                return m[1]
    else:
        # nested ternary (`a ? b : c ? d : e`): the else arm is the next
        # level's JMPZ, not an else-jump — try the chain reconstruction
        m = _ternary_chain(ctx, i, end)
        if m is not None:
            return m[1]
        tp = _ternary_plan(ctx, i, end)
        if tp is not None:
            m = _ternary_exec(ctx, tp[1])
            if m is not None:
                return m[1]
    # A closure body's if/else where the then arm ends in RETURN has no
    # else-jump in the wire (the return makes it dead).  Restore the
    # explicit else: `if (c) { return A; } else { return B; }` reads better
    # than a bare fall-through return, and is the source shape for the
    # encoder's no-JMP lowering.
    if (
        not hasElse
        and not isCase
        and ctx.meta.get("closure")
        and t > i + 1
        and t < end
        and ctx.op[t - 1] == 62
    ):
        ctx.line(n)
        ctx.w(f"if ({condTxt}) {{")
        ctx.idp += 1
        emit_region(ctx, i + 1, t)
        ctx.idp -= 1
        ctx.w("} else {")
        ctx.idp += 1
        emit_region(ctx, t, end)
        ctx.idp -= 1
        ctx.w("}")
        ctx.emitted += 1
        return end
    ctx.line(n)
    ctx.w(f"if ({condTxt}) {{")
    cont = t
    ctx.idp += 1
    if hasElse:
        cont = ctx.jt[t - 1]  # node before target = then-exit JMP
        shared = _shared_tail_assign(ctx, i, t, cont, end)
        if shared is not None:
            cont = shared
        ctx.bk(t - 1)
        emit_region(ctx, i + 1, t - 1)
        ctx.idp -= 1
        elseHdr = len(ctx.out)
        ctx.w("} else {")
        ctx.idp += 1
        start = len(ctx.out)
        emit_region(ctx, t, cont)
        # an else arm that only prepares a value inlined at its use emits
        # no statement of its own; with a terminating then arm the else is
        # the only fall-through path, so `else { }` is pure noise
        elseLines = [
            s
            for s in ctx.out[start:]
            if s.strip() and not s.strip().startswith(("//", "/*"))
        ]
        if not elseLines and (
            _region_ends_terminal(ctx, i + 1, t - 1)
            or not _region_values_escape(ctx, t, cont)
        ):
            del ctx.out[elseHdr:]
    else:
        emit_region(ctx, i + 1, t)
    ctx.idp -= 1
    ctx.w("}")
    ctx.emitted += 1
    return cont


def emit_jmp_set(ctx: LiftContext, i: int, end: int) -> int:
    """`a ?: b` — the JMP_SET short-circuit (Part C). The alternative region computes into the same
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


__all__ = [
    "emit_if",
    "emit_jmp",
    "emit_jmp_set",
    "emit_return",
    "emit_try",
    "loop_exit_stmt",
]
