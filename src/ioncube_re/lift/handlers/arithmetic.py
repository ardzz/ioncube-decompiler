"""Arithmetic/comparison/unary expression families: the value-producing
ops that store a string into the node's res temp slot via ``ctx.def_temp``
(the value renders at its single use site)."""

from __future__ import annotations

from ..model import LiftContext
from ..operand import bare, concat_pair, zval_name
from ..registry import opcode_handler

_BIN = {
    1: "+",
    2: "-",
    3: "*",
    4: "/",
    5: "%",
    6: "<<",
    7: ">>",
    9: "|",
    10: "&",
    11: "^",
    12: "**",
    15: "xor",
    16: "===",
    17: "!==",
    18: "==",
    19: "!=",
    20: "<",
    21: "<=",
    170: "<=>",
}
_UN = {14: "!", 13: "~", 52: "(bool)"}
_FN1 = {
    121: "strlen",
    188: "count",
    189: "get_class",
    190: "get_called_class",
    191: "gettype",
}


@opcode_handler(*_BIN)
def _binop(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    op = ctx.op[i]
    if op == 15:
        # the match(true) lowering may run [cmp][BOOL_XOR true][JMPNZ] —
        # try the match degradation before the plain xor binop
        from ..switches import emit_match

        m = emit_match(ctx, i, end)
        if m is not None:
            return m
    r = ctx.render
    e = "(" + r.ch(r.ex_op1(n)) + " " + _BIN[op] + " " + r.ch(r.ex_op2(n)) + ")"
    return ctx.def_temp(n, e, i)


@opcode_handler(8, 53)  # CONCAT / FAST_CONCAT — no defensive parens (benchmark gap)
def _concat(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, concat_pair(r.ch(r.ex_op1(n)), r.ch(r.ex_op2(n))), i)


@opcode_handler(*_UN)
def _unop(ctx: LiftContext, i: int, end: int) -> int:
    if ctx.op[i] == 14:
        # the match(true) lowering runs [cmp][BOOL_NOT][JMPNZ] — try the
        # match degradation before the plain !() unary
        from ..switches import emit_match

        m = emit_match(ctx, i, end)
        if m is not None:
            return m
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, _UN[ctx.op[i]] + "(" + r.ch(r.ex_op1(n)) + ")", i)


@opcode_handler(138)  # INSTANCEOF
def _instanceof(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    # the class operand is a NAME, not a string literal: the zval form
    # escapes backslashes (`BlestaAi\\Client`) — resolve the bare name
    e2 = n.ent.get("op2")
    cls = None
    if e2 is not None and e2.kind == 1 and e2.raw < len(ctx.zvals):
        cls = zval_name(ctx.zvals[e2.raw])
    if cls is None:
        cls = bare(r.ch(r.ex_op2(n)))
    return ctx.def_temp(n, r.ch(r.ex_op1(n)) + " instanceof " + cls, i)


@opcode_handler(*_FN1)
def _fn1(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, _FN1[ctx.op[i]] + "(" + r.ch(r.ex_op1(n)) + ")", i)


@opcode_handler(169)  # COALESCE
def _coalesce(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    # the `$a ?? $b` lowering stores the fallback block's jump target in
    # op2 (a kind-0 raw = QM node + 1): `if ($a !== null) ->skip else
    # QM $b` — fold the QM's value in and consume it
    e2 = n.ent.get("op2")
    if e2 and e2.kind == 0 and 0 < e2.raw - 1 < ctx.thr and ctx.op[e2.raw - 1] == 31:
        fb = ctx.nodes[e2.raw - 1]
        fe = fb.ent.get("res")
        if fe and fe.kind == 2 and fb.res // 16 == n.res // 16:
            v = r.ch(r.ex_op1(fb))
            if v is not None:
                ctx.bk(e2.raw - 1)
                ctx.emitted += 1
                ctx.tempExpr[n.res // 16] = r.ch(r.ex_op1(n)) + " ?? " + v
                return e2.raw
    return ctx.def_temp(n, r.ch(r.ex_op1(n)) + " ?? " + r.ch(r.ex_op2(n)), i)


@opcode_handler(31)  # QM_ASSIGN
def _qm_assign(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    return ctx.def_temp(n, ctx.render.ch(ctx.render.ex_op1(n)), i)


@opcode_handler(51, 123)  # CAST / TYPE_CHECK
def _cast(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    op = ctx.op[i]
    from ..operand import cast_name, typecheck_bits

    r = ctx.render
    if op == 123:
        # TYPE_CHECK carries a 1<<type BITMASK (64 = is_string,
        # 128 = is_array on the corpus) — not the plain type enum CAST uses
        e = typecheck_bits(n.ext)
        if "gettype($x)" in e:
            e = e.replace("gettype($x)", "gettype(" + r.ch(r.ex_op1(n)) + ")")
        else:
            e = e + "(" + r.ch(r.ex_op1(n)) + ")"
    else:
        e = "(" + cast_name(n.ext) + ")" + "(" + r.ch(r.ex_op1(n)) + ")"
    return ctx.def_temp(n, e, i)
