"""The misc families: echo/throw/exit/include, declare statements, the
`@` silence operator, statics and closures, the by-name one-liners, and
the pure bookkeeping set (NOP/EXT_*/FREE/RECV/OP_DATA/CATCH/... — nodes
consumed into structures, counted, never rendered)."""

from __future__ import annotations

import re

from ...opcodes import OPNAMES
from ..model import LiftContext
from ..operand import bare
from ..registry import opcode_handler


@opcode_handler(136)  # ECHO
def _echo(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    from ..operand import unwrap

    ctx.line(n)
    ctx.w("echo " + unwrap(ctx.render.ch(ctx.render.ex_op1(n))) + ";")
    ctx.emitted += 1
    return i + 1


@opcode_handler(108)  # THROW
def _throw(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    from ..operand import unwrap

    ctx.line(n)
    ctx.w("throw " + unwrap(ctx.render.ch(ctx.render.ex_op1(n))) + ";")
    ctx.emitted += 1
    return i + 1


@opcode_handler(79)  # EXIT
def _exit(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    ctx.line(n)
    v = ctx.render.ex_op1(n)
    ctx.w("exit" + (f"({v})" if v is not None and v != "null" else "") + ";")
    ctx.emitted += 1
    return i + 1


@opcode_handler(73)  # INCLUDE_OR_EVAL
def _include(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    ctx.line(n)
    k = {
        1: "eval",
        2: "include",
        4: "include_once",
        8: "require",
        16: "require_once",
        3: "include_once",
        5: "require_once",
    }
    ctx.w(k.get(n.ext, "include") + " " + ctx.render.ch(ctx.render.ex_op1(n)) + ";")
    ctx.emitted += 1
    return i + 1


@opcode_handler(141, 144, 145, 146)  # DECLARE_FUNCTION/CLASS/...
def _declare(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    ctx.line(n)
    ctx.w(
        f"/* {OPNAMES.get(ctx.op[i], 'DECLARE')} op1={r.opnd_text(n, 'op1')} "
        f"op2={r.opnd_text(n, 'op2')} */"
    )
    ctx.emitted += 1
    return i + 1


# ---- silence: the `@` operator ----


@opcode_handler(57)  # BEGIN_SILENCE
def _begin_silence(ctx: LiftContext, i: int, end: int) -> int:
    # the marker temp is bookkeeping, not a value (their comment: "a
    # placeholder would pollute LIFO temp reconciliation")
    ctx.silence.append(set(ctx.tempExpr.keys()))
    ctx.bk(i)
    return i + 1


@opcode_handler(58)  # END_SILENCE
def _end_silence(ctx: LiftContext, i: int, end: int) -> int:
    before = ctx.silence.pop() if ctx.silence else set()
    # the silenced expression usually lives in the newest temp produced
    # inside the window (`$x = @curl_getinfo(...)`); wrap it so the @ is
    # not lost — but only if that temp was produced inside the window
    for k in reversed(list(ctx.tempExpr.keys())):
        if k in before:
            continue
        e = ctx.tempExpr[k]
        if not e.startswith("@"):
            ctx.tempExpr[k] = "@" + e
        break
    ctx.bk(i)
    return i + 1


# ---- statics, lexicals, closures ----


@opcode_handler(181)  # BIND_STATIC
def _bind_static(ctx: LiftContext, i: int, end: int) -> int:
    # the PHP 8 match lowering opens with a BIND_STATIC unit run
    # ([BIND_STATIC][JMP_NULL][JMPNZ]xN) — try the match degradation first
    from ..switches import emit_match

    m = emit_match(ctx, i, end)
    if m is not None:
        return m
    # `static $x` — the static_variables table (their default rendering)
    # is not decoded from our wire; the default initializer is not
    # recoverable, so the statement renders bare
    n = ctx.nodes[i]
    ctx.line(n)
    e = n.ent.get("op1")
    if e and e.kind == 8:
        ctx.w("static " + ctx.cv_name(e.raw) + ";")
    else:
        ctx.w(f"/* BIND_STATIC op1={ctx.render.opnd_text(n, 'op1')} */")
    ctx.emitted += 1
    return i + 1


@opcode_handler(180)  # BIND_LEXICAL
def _bind_lexical(ctx: LiftContext, i: int, end: int) -> int:
    # the closure's `use (...)` clause is rendered by the DECLARE_LAMBDA
    # look-ahead; must NOT consume the closure temp in op1
    ctx.bk(i)
    return i + 1


@opcode_handler(142)  # DECLARE_LAMBDA_FUNCTION
def _declare_lambda(ctx: LiftContext, i: int, end: int) -> int:
    # `use (...)` names: the BIND_LEXICAL run that follows, targeting this
    # node's res temp, in source order (their _collect_lexical_uses)
    n = ctx.nodes[i]
    reskey = _slot(n)
    uses: list[str] = []
    j = i + 1
    while j < ctx.thr:
        nj = ctx.nodes[j]
        # ktab often garbles BIND_LEXICAL (180) into FETCH_THIS (182);
        # an op1 = closure-temp + op2 = CV is a lexical bind either way
        if ctx.op[j] != 180 and not (
            ctx.op[j] == 182
            and nj.ent.get("op1")
            and (nj.ent["op1"].kind & 6)
            and reskey is not None
            and nj.op1 // 16 == reskey
        ):
            break
        ne1, ne2 = nj.ent.get("op1"), nj.ent.get("op2")
        if reskey is not None and ne1 and (ne1.kind & 6) and nj.op1 // 16 != reskey:
            break
        if ne2 and ne2.kind == 8:
            # ext bit 1 = by-ref binding (`use (&$x)`)
            uses.append(("&" if nj.ext & 1 else "") + ctx.cv_name(ne2.raw))
        j += 1
    clause = (" use (" + ", ".join(uses) + ")") if uses else ""
    # the closure body renders from its nested sub-wire (pipeline
    # pre-pass, source order); without one the placeholder comment stands
    expr = f"function (){clause} {{ /* closure body: the {{closure}} component */ }}"
    bodies = ctx.meta.get("closureBodies")
    if bodies:
        sig, ret, stmts = bodies.pop(0)
        # strip the listing's line markers + the accounting comment: the
        # arrow-fn detection needs the bare statement text
        core = re.sub(r"(?m)^\s*// line \d+\s*$\n?", "", stmts)
        core = re.sub(r"/\* \d+ nodes[^*]*\*/\s*$", "", core).strip()
        head = f"function ({sig}){clause}" + (f": {ret}" if ret else "")
        m = re.fullmatch(r"return (.+);", core, re.S)
        if m is not None and ret and "->" not in sig:
            # a single-return body with a declared type is an arrow fn
            expr = f"fn ({sig}){clause}: {ret} => {m.group(1).strip()}"
        else:
            expr = f"{head} {{\n{stmts}\n}}"
    ctx.emitted += 1
    for k in range(i + 1, j):
        ctx.bk(k)
    if reskey is not None:
        ctx.tempExpr[reskey] = expr
    return j


# ---- the by-name one-liners ----


@opcode_handler(122)  # DEFINED
def _defined(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    nm = ctx.render.ch(ctx.render.ex_op1(n))
    return ctx.def_temp(n, "defined(" + (nm if nm != "null" else "'?'") + ")", i)


@opcode_handler(171)  # FUNC_NUM_ARGS
def _func_num_args(ctx: LiftContext, i: int, end: int) -> int:
    return ctx.def_temp(ctx.nodes[i], "func_num_args()", i)


@opcode_handler(140)  # MAKE_REF
def _make_ref(ctx: LiftContext, i: int, end: int) -> int:
    return ctx.def_temp(ctx.nodes[i], ctx.render.ch(ctx.render.ex_op1(ctx.nodes[i])), i)


@opcode_handler(156)  # SEPARATE (refcount copy-on-write; identity)
def _separate(ctx: LiftContext, i: int, end: int) -> int:
    return ctx.def_temp(ctx.nodes[i], ctx.render.ch(ctx.render.ex_op1(ctx.nodes[i])), i)


# ---- the bookkeeping set (consumed into structures; counted, not rendered) ----


@opcode_handler(0, 63, 64, 70, 101, 102, 103, 104, 105, 107, 109, 124, 127, 137, 164)
def _bookkeeping(ctx: LiftContext, i: int, end: int) -> int:
    # NOP/EXT_*, FREE/FE_FREE, FETCH_CLASS, RECV*, OP_DATA,
    # VERIFY_RETURN_TYPE, CATCH bind — bookkeeping
    ctx.bookkept += 1
    return i + 1


@opcode_handler(66)  # SEND_VAR_EX
def _send_var_ex(ctx: LiftContext, i: int, end: int) -> int:
    # inside a call's SEND run this is collected as an argument (the _SEND
    # tuple); a leftover outside a run is the duplicated-arg lowering of a
    # try/catch call — the call is already rendered in both arms
    ctx.bookkept += 1
    return i + 1


@opcode_handler(50, 65, 67, 106, 117, 119, 120)
def _send_orphan(ctx: LiftContext, i: int, end: int) -> int:
    # the remaining SEND_* family outside a collected call run: the same
    # orphan contract as SEND_VAL_EX/SEND_FUNC_ARG (116/183 live in
    # calls.py) — the call renders at its structured site
    ctx.bookkept += 1
    return i + 1


@opcode_handler(110)  # CLONE
def _clone(ctx: LiftContext, i: int, end: int) -> int:
    return ctx.def_temp(
        ctx.nodes[i], "clone " + ctx.render.ch(ctx.render.ex_op1(ctx.nodes[i])), i
    )


@opcode_handler(111)  # RETURN_BY_REF
def _return_by_ref(ctx: LiftContext, i: int, end: int) -> int:
    # `return &$x;` is declared on the signature, which the recovery
    # doesn't carry — render the value return
    from ..structurer import emit_return

    return emit_return(ctx, i, end)


@opcode_handler(193)  # MATCH
def _match_gettype(ctx: LiftContext, i: int, end: int) -> int:
    # no sample lowers a real `match` — the wire's 193 sites are the
    # encoder's gettype lowering (the res feeds a `== 'NULL'` check or a
    # `'type ' . $x` message): render the gettype expression
    return ctx.def_temp(
        ctx.nodes[i],
        "gettype(" + ctx.render.ch(ctx.render.ex_op1(ctx.nodes[i])) + ")",
        i,
    )


@opcode_handler(195, 197)  # MATCH_ERROR / CHECK_UNDEF_ARGS
def _match_tail(ctx: LiftContext, i: int, end: int) -> int:
    # the runtime throw-tails of the lowered `match`/param validation —
    # the arms themselves carry the visible semantics
    ctx.bookkept += 1
    return i + 1


def _slot(n) -> int | None:
    e = n.ent.get("res")
    return n.res // 16 if e and (e.kind & 6) else None
