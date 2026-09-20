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

import re

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
    if name is not None and "\\" in name and op in (59, 61, 69):
        # an unqualified function call inside a namespace arrives with the
        # ns-qualified name (`blesta\app\models\is_dir`); the runtime falls
        # back to the global function — render the plain name
        name = name.rsplit("\\", 1)[-1]
    if op == 128:
        # INIT_DYNAMIC_CALL: the callee is a runtime value — a closure CV
        # ($inc()) or temp ($apply($f)) — not an interned name; render the
        # variable-function form directly
        callee = r.ex(n, "op2")
        if callee is not None and re.match(r"^\$[A-Za-z_]", callee):
            expr0 = callee + "("  # args appended below
        else:
            callee = None
    else:
        callee = None
    if name is None and callee is None and op != 128:
        # the callee name is not recoverable (heap-pointer interned name) —
        # an unnameable call is a comment, not fabricated syntax
        ctx.line(n)
        ctx.w("/* call: callee name not recoverable */")
        ctx.emitted += 1
        j = i + 1
        while j < end and not (ctx.op[j] is None or ctx.op[j] in _DO):
            ctx.bk(j)
            j += 1
        if j < end and ctx.op[j] is not None:
            ctx.bk(j)
            j += 1
        return j
    args: list[str] = []
    j = i + 1
    consumed: set[int] = set()  # arg-expression nodes (emitted, not bookkept)
    while j < end:
        o = ctx.op[j]
        if o is not None and o in _SEND:
            # SEND_UNPACK (165): `...$xs` argument spreading
            v = r.ch(r.ex(ctx.nodes[j], "op1"))
            args.append(("..." + v) if o == 165 else v)
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
            # 514 = parent, 513 = self (the default sentinel); anything else
            # keeps a `self` fallback — `/*class-N*/::` is a parse error
            cls = {514: "parent", 515: "static"}.get(raw1.raw, "self")
        else:
            cls = r.callee_name(n, "op1") or "self /*class-unresolved*/"
        if cls.startswith("self") and ctx.meta.get("classDepth") is False:
            # no class scope (a free-function component): `self::` is a
            # compile error — an undefined-class name keeps the listing
            # lint-valid with a visible trace
            cls = "UnresolvedScope"
        expr = f"{cls}::{name}(" + ", ".join(args) + ")"
    elif op in (112, 118):
        # a receiver method call: $obj->name(...) — INIT_DYNAMIC_CALL (128)
        # has NO receiver; its op2 CV/var IS the callee (a closure value)
        expr = f"{r.obj(r.ex_op1(n))}->{name}(" + ", ".join(args) + ")"
    elif op == 128 and callee is not None:
        expr = callee + "(" + ", ".join(args) + ")"
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
            slot = doN.res // 16
            if len(ctx.tempUses.get(slot, [])) == 1:
                # the single reader inlines the call at its use
                ctx.tempExpr[slot] = expr
            else:
                # a multi-read result (loop condition + row destructure)
                # keeps a named temp statement: the later refs render the
                # same $Vn, and the side-effecting call stays single
                ctx.line(n)
                ctx.w(f"$V{slot - 5} = " + unwrap(expr) + ";")
                ctx.tempExpr[slot] = expr
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
    if cls is None:
        # `new (` is a parse error; the bare stdClass placeholder keeps
        # the statement valid while flagging the unresolved ctor target
        cls = "\\stdClass /*class-unresolved*/"
    args = []
    j = i + 1
    consumed: set[int] = set()
    while j < end:
        o = ctx.op[j]
        if o is not None and o in _SEND:
            v = ctx.render.ch(ctx.render.ex(ctx.nodes[j], "op1"))
            args.append(("..." + v) if o == 165 else v)
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
        slot = n.res // 16
        if len(ctx.tempUses.get(slot, [])) == 1:
            ctx.tempExpr[slot] = expr
        else:
            # a multi-read ctor result keeps a named temp statement, the
            # same contract as the multi-read DO_FCALL result
            ctx.line(n)
            ctx.w(f"$V{slot - 5} = " + unwrap(expr) + ";")
            ctx.tempExpr[slot] = expr
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
            items.append(
                k + " => " + v
                if (
                    k is not None and k not in ("0", "null") and nj.ent["op2"].kind != 0
                )
                else v
            )
            j += 1
            continue
        # an expression def between the elements: the next element being
        # built (FETCH_CONSTANT interleaved with the AAE run). A construct
        # starter (INIT_ARRAY / call INIT) ENDS this run — the remaining
        # AAEs land at statement level and extend the literal via the
        # registry handler (handlers/arrays.py ADD_ARRAY_ELEMENT)
        if (
            o is not None
            and o != 71
            and o not in _INIT
            and o != 68
            and ctx.nodes[j].ent.get("res")
            and (ctx.nodes[j].ent["res"].kind & 6)
        ):
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
