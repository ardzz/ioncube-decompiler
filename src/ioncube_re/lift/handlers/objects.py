"""Object/property families: FETCH_OBJ_* property reads and writes,
unset chains, PRE_INC/DEC_OBJ, ISSET_ISEMPTY_PROP_OBJ, FETCH_THIS."""

from __future__ import annotations

from ..model import LiftContext
from ..operand import bare
from ..registry import opcode_handler


@opcode_handler(82, 85, 91, 88, 94, 98)  # FETCH_OBJ_* (container->prop)
def _fetch_obj(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, r.obj(r.ex_op1(n)) + "->" + bare(r.ch(r.ex_op2(n))), i)


@opcode_handler(81, 84, 90, 87, 93, 96)  # FETCH_DIM_*
def _fetch_dim(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, r.ch(r.ex_op1(n)) + "[" + r.ch(r.ex_op2(n)) + "]", i)


@opcode_handler(182)  # FETCH_THIS (incl. the ungarbled ISSET_ISEMPTY_THIS)
def _fetch_this(ctx: LiftContext, i: int, end: int) -> int:
    return ctx.def_temp(ctx.nodes[i], "$this", i)


@opcode_handler(97)  # FETCH_OBJ_UNSET
def _fetch_obj_unset(ctx: LiftContext, i: int, end: int) -> int:
    # a fetch staged for unset(): res temp feeds the UNSET_OBJ chain
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, r.obj(r.ex_op1(n)) + "->" + bare(r.ch(r.ex_op2(n))), i)


@opcode_handler(76)  # UNSET_OBJ: unset($obj->prop)
def _unset_obj(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    # the op1 temp is the FETCH_OBJ_UNSET-resolved receiver chain
    ctx.line(n)
    ctx.w("unset(" + r.obj(r.ex(n, "op1")) + "->"
          + bare(r.ch(r.ex(n, "op2"))) + ");")
    ctx.emitted += 1
    return i + 1


@opcode_handler(132, 133)  # PRE_INC_OBJ / PRE_DEC_OBJ
def _pre_incdec_obj(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    sym = "++" if ctx.op[i] == 132 else "--"
    if n.ent.get("op2"):
        e = r.obj(r.ex_op1(n)) + "->" + bare(r.ch(r.ex_op2(n)))
    else:
        e = r.ch(r.ex_op1(n))
    return ctx.def_temp(n, sym + e, i)


@opcode_handler(148)  # ISSET_ISEMPTY_PROP_OBJ (ext&2 = empty)
def _isset_prop(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    fn = "empty" if (n.ext & 2) else "isset"
    arg = r.obj(r.ex_op1(n)) + "->" + bare(r.ch(r.ex_op2(n)))  # bare prop (ic_lift parity)
    return ctx.def_temp(n, fn + "(" + arg + ")", i)
