"""Arithmetic/comparison/unary expression families: the value-producing
ops that store a string into the node's res temp slot via ``ctx.def_temp``
(the value renders at its single use site)."""

from __future__ import annotations

from ..model import LiftContext
from ..operand import bare, concat_pair
from ..registry import opcode_handler

_BIN = {1: "+", 2: "-", 3: "*", 4: "/", 5: "%", 6: "<<", 7: ">>", 9: "|",
        10: "&", 11: "^", 12: "**", 15: "xor", 16: "===", 17: "!==",
        18: "==", 19: "!=", 20: "<", 21: "<=", 170: "<=>"}
_UN = {14: "!", 13: "~", 52: "(bool)"}
_FN1 = {121: "strlen", 188: "count", 189: "get_class", 190: "get_called_class", 191: "gettype"}


@opcode_handler(*_BIN)
def _binop(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    op = ctx.op[i]
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
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, _UN[ctx.op[i]] + "(" + r.ch(r.ex_op1(n)) + ")", i)


@opcode_handler(138)  # INSTANCEOF
def _instanceof(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, r.ch(r.ex_op1(n)) + " instanceof "
                        + bare(r.ch(r.ex_op2(n))), i)


@opcode_handler(*_FN1)
def _fn1(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, _FN1[ctx.op[i]] + "(" + r.ch(r.ex_op1(n)) + ")", i)


@opcode_handler(169)  # COALESCE
def _coalesce(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, r.ch(r.ex_op1(n)) + " ?? " + r.ch(r.ex_op2(n)), i)


@opcode_handler(31)  # QM_ASSIGN
def _qm_assign(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    return ctx.def_temp(n, ctx.render.ch(ctx.render.ex_op1(n)), i)


@opcode_handler(51, 123)  # CAST / TYPE_CHECK
def _cast(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    op = ctx.op[i]
    from ..operand import cast_name
    r = ctx.render
    e = (("(" + cast_name(n.ext) + ")") if op == 51 else cast_name(n.ext)) \
        + "(" + r.ch(r.ex_op1(n)) + ")"
    return ctx.def_temp(n, e, i)
