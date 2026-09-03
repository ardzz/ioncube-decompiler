"""Expression collectors: the multi-node constructs that build one value —
call argument runs (INIT_FCALL..DO_FCALL), object construction (NEW..DO),
and array literals (INIT_ARRAY + ADD_ARRAY_ELEMENT runs).

Ported from the emitter's PHP-first fixed shape (M6-SUBWIRE §7.6): argument
expressions between the SENDs render in place through the full statement
dispatcher (call args legally contain the ternary lowering, inline ASSIGN,
POST_INC); nested INIT/NEW/INIT_ARRAY recurse; ``consumed``/``acct`` keep
the accounting single-counted.

The DO node is the walk's exact stopping point — never behind a real
statement (a forward scan here swallowed the NEXT call's DO when an
argument expression interrupted the SEND run). THIS is the one place that
rule lives (M6-SUBWIRE §7.6).
"""

from __future__ import annotations

from .model import LiftContext
from .operand import unwrap

# the SEND tuple (SEND_FUNC_ARG 183 = the ungarbled +2 form, §7.5)
_SEND = (65, 116, 117, 66, 67, 106, 50, 165, 119, 120, 183)
_DO = (60, 129, 130, 131)
_INIT = (59, 61, 69, 112, 113, 118, 128)


def collect_call(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    op = ctx.op[i]
    r = ctx.render
    name = r.callee_name(n, "op2")
    args: list[str] = []
    j = i + 1
    consumed: set[int] = set()  # arg-expression nodes (emitted, not bookkept)
    while j < end:
        o = ctx.op[j]
        if o is not None and o in _SEND:
            args.append(r.ch(r.ex(ctx.nodes[j], "op1")))
            j += 1
            continue
        if o is not None and o == 100:  # CHECK_FUNC_ARG by-ref glue
            j += 1
            continue
        if o is not None and (o in _INIT or o == 68):
            j = collect_new(ctx, j, end) if o == 68 else collect_call(ctx, j, end)
            continue
        if o is not None and o == 71:  # an array-literal argument
            j = collect_array(ctx, j, end)
            continue
        if o is None or o in _DO:
            break
        # an argument being built between the SENDs: a value op, or the
        # ternary/short-circuit lowering (JMPZ / QM_ASSIGN / JMP), or an
        # inline ASSIGN (`foo($x = 5)`). Render it in place through the
        # full statement dispatcher and keep collecting the SEND run —
        # the DO stays the stopping point.
        from .emitter import emit_node  # late import: emitter <-> collectors cycle

        nx = emit_node(ctx, j, end)
        if nx <= j:
            break
        for k in range(j, nx):
            consumed.add(k)
            ctx.acct.add(k)
        j = nx
    if op == 113:  # INIT_STATIC_METHOD_CALL
        raw1 = n.ent.get("op1")
        if raw1 is not None and raw1.kind == 0:
            cls = "parent" if raw1.raw == 514 else f"/*class-{raw1.raw}*/"
        else:
            cls = r.callee_name(n, "op1")
        expr = f"{cls}::{name}(" + ", ".join(args) + ")"
    elif op in (112, 118, 128):
        expr = f"{r.obj(r.ex_op1(n))}->{name}(" + ", ".join(args) + ")"
    else:
        expr = f"{name}(" + ", ".join(args) + ")"
    # the DO must be the walk's stopping point (see module docstring)
    if j < end and ctx.op[j] is not None and ctx.op[j] in _DO:
        doN = ctx.nodes[j]
        ctx.emitted += 1
        for k in range(i, j):
            if k not in consumed:
                ctx.bk(k)
        e = doN.ent.get("res")
        if e and (e.kind & 6):
            ctx.tempExpr[doN.res // 16] = expr
        else:
            ctx.line(n)
            ctx.w(unwrap(expr) + ";")
        return j + 1
    ctx.line(n)
    ctx.w(unwrap(expr) + "; /* no DO_FCALL seen */")
    ctx.emitted += 1
    for k in range(i + 1, j):
        if k not in consumed:
            ctx.bk(k)
    return j


def collect_new(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    cls = ctx.render.callee_name(n, "op1")
    args = []
    j = i + 1
    consumed: set[int] = set()
    while j < end:
        o = ctx.op[j]
        if o is not None and o in _SEND:
            args.append(ctx.render.ch(ctx.render.ex(ctx.nodes[j], "op1")))
            j += 1
            continue
        if o is not None and o == 100:  # CHECK_FUNC_ARG glue
            j += 1
            continue
        if o is None or o in _DO:
            break
        # a ctor argument being built — same full-dispatcher recursion as
        # collect_call (the func-arg fetch chain: FETCH_OBJ_FUNC_ARG + the
        # ungarbled SEND_FUNC_ARG; Action.php n102-106)
        from .emitter import emit_node  # late import: emitter <-> collectors cycle

        nx = emit_node(ctx, j, end)
        if nx <= j:
            break
        for k in range(j, nx):
            consumed.add(k)
            ctx.acct.add(k)
        j = nx
    expr = f"new {cls}(" + ", ".join(args) + ")"
    if j < end and ctx.op[j] is not None and ctx.op[j] in _DO:
        j += 1
    e = n.ent.get("res")
    if e and (e.kind & 6):
        ctx.tempExpr[n.res // 16] = expr
    ctx.emitted += 1
    for k in range(i + 1, j):
        if k not in consumed:
            ctx.bk(k)
    return j


def collect_array(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    items = []
    j = i
    consumed: set[int] = set()
    while j < end:
        o = ctx.op[j]
        if o is not None and (o == 72 or (o == 71 and j == i)):
            # ADD_ARRAY_ELEMENT continues the run; INIT_ARRAY only starts it
            nj = ctx.nodes[j]
            v = r.ch(r.ex_op1(nj))
            k = r.ex(nj, "op2") if nj.ent.get("op2") else None
            items.append(k + " => " + v
                         if (k is not None and k not in ("0", "null")
                             and nj.ent["op2"].kind != 0) else v)
            j += 1
            continue
        # an expression def between the elements: the next element being
        # built (FETCH_CONSTANT interleaved with the AAE run). A construct
        # starter (INIT_ARRAY / call INIT) ENDS this run — the remaining
        # AAEs land at statement level and extend the literal via the
        # registry handler (handlers/arrays.py ADD_ARRAY_ELEMENT)
        if o is not None and o != 71 and o not in _INIT and o != 68 \
                and ctx.nodes[j].ent.get("res") \
                and (ctx.nodes[j].ent["res"].kind & 6):
            from .emitter import emit_node  # late import: emitter <-> collectors cycle

            nx = emit_node(ctx, j, end)
            if nx > j:
                for k in range(j, nx):
                    consumed.add(k)
                    ctx.acct.add(k)
                j = nx
                continue
        break
    expr = "[" + ", ".join(items) + "]"
    e = n.ent.get("res")
    if e and (e.kind & 6):
        ctx.tempExpr[n.res // 16] = expr
    ctx.emitted += 1
    for k in range(i + 1, j):
        if k not in consumed:
            ctx.bk(k)
    return j


__all__ = ["collect_array", "collect_call", "collect_new"]
