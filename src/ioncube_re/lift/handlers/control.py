"""Control-flow families: the jump/branch/loop/switch/return opcodes route
to the structurer and loops modules; the orphaned loop glue degrades to
bookkeeping."""

from __future__ import annotations

from .. import loops, structurer, switches
from ..model import LiftContext
from ..registry import opcode_handler


@opcode_handler(42)  # JMP
def _jmp(ctx: LiftContext, i: int, end: int) -> int:
    return structurer.emit_jmp(ctx, i, end)


@opcode_handler(43, 44, 46, 47)  # JMPZ / JMPNZ / JMPZ_EX / JMPNZ_EX
def _branch(ctx: LiftContext, i: int, end: int) -> int:
    # the match(true) lowering is a [cmp][BOOL_NOT|xor|IS_IDENTICAL true]
    # [JMPNZ] chain — try the match degradation from its branch node first
    if ctx.op[i] == 44 and i >= 2 and ctx.op[i - 1] in (14, 15, 16):
        from ..switches import emit_match

        m = emit_match(ctx, i - 1, end)
        if m is not None:
            return m
    return structurer.emit_if(ctx, i, end, ctx.op[i])


@opcode_handler(152)  # JMP_SET — the `a ?: b` short-circuit (full, Part C)
def _jmp_set(ctx: LiftContext, i: int, end: int) -> int:
    return structurer.emit_jmp_set(ctx, i, end)


@opcode_handler(62)  # RETURN
def _return(ctx: LiftContext, i: int, end: int) -> int:
    return structurer.emit_return(ctx, i, end)


@opcode_handler(77, 125)  # FE_RESET_R / FE_RESET_RW
def _fe_reset(ctx: LiftContext, i: int, end: int) -> int:
    return loops.emit_foreach(ctx, i, end)


@opcode_handler(78, 126)  # FE_FETCH_R / FE_FETCH_RW (orphans)
def _fe_fetch_orphan(ctx: LiftContext, i: int, end: int) -> int:
    # the foreach body consumer; emit_foreach handles it in-pattern
    ctx.bk(i)
    return i + 1


@opcode_handler(48, 194)  # CASE / CASE_STRICT
def _case(ctx: LiftContext, i: int, end: int) -> int:
    return switches.emit_case(ctx, i, end)


@opcode_handler(185, 186)  # SWITCH_LONG / SWITCH_STRING headers (ungarbled)
def _switch_header(ctx: LiftContext, i: int, end: int) -> int:
    return switches.emit_switch_header(ctx, i, end)


@opcode_handler(149)  # HANDLE_EXCEPTION
def _handle_exception(ctx: LiftContext, i: int, end: int) -> int:
    # the exception-handler landing pad.  In a call-expression region the
    # encoder also carries the call result through it (res = op1), e.g.
    # the last term of a short-circuit condition: define the result temp
    # so the JMPZ reader sees the call expression instead of an undefined
    # $T.
    n = ctx.nodes[i]
    e = n.ent.get("res")
    o = n.ent.get("op1")
    if e is not None and (e.kind & 6) and o is not None:
        return ctx.def_temp(n, ctx.render.ex_op1(n), i)
    ctx.bk(i)
    return i + 1
