"""Call-construction families: the INIT_FCALL/INIT_METHOD_CALL/NEW/
INIT_ARRAY constructs route to the collectors (the multi-node walks), and
the call glue that can land orphaned degrades to bookkeeping."""

from __future__ import annotations

from ..collectors import collect_array, collect_call, collect_new
from ..model import LiftContext
from ..registry import opcode_handler


@opcode_handler(59, 61, 69, 112, 113, 118, 128)  # the INIT_* family
def _init_call(ctx: LiftContext, i: int, end: int) -> int:
    return collect_call(ctx, i, end)


@opcode_handler(68)  # NEW
def _new(ctx: LiftContext, i: int, end: int) -> int:
    return collect_new(ctx, i, end)


@opcode_handler(71)  # INIT_ARRAY
def _init_array(ctx: LiftContext, i: int, end: int) -> int:
    return collect_array(ctx, i, end)


# ---- the orphan-glue families (bookkeeping when the walk lands on them) ----


@opcode_handler(183)  # SEND_FUNC_ARG (ungarbled from SWITCH_LONG, §7.5 garble)
def _send_func_arg(ctx: LiftContext, i: int, end: int) -> int:
    # an arg send consumed by collect_call's SEND tuple; landing here means
    # the INIT frame was never reached by the walk — the arg cannot render
    ctx.bk(i)
    return i + 1


@opcode_handler(116)  # SEND_VAL_EX (benchmark-2 §4's family gap)
def _send_val_ex(ctx: LiftContext, i: int, end: int) -> int:
    # same orphan contract as SEND_FUNC_ARG: consumed by collect_call's
    # SEND tuple; landing here means the INIT was consumed elsewhere
    ctx.bk(i)
    return i + 1


@opcode_handler(60, 129, 130, 131)  # DO_FCALL / DO_ICALL / DO_UCALL / BY_NAME
def _do_fcall_orphan(ctx: LiftContext, i: int, end: int) -> int:
    # the call completes inside collect_call/collect_new; landing here the
    # INIT was consumed elsewhere (e.g. its "no DO_FCALL seen" fallback)
    ctx.bk(i)
    return i + 1


@opcode_handler(100)  # CHECK_FUNC_ARG
def _check_func_arg(ctx: LiftContext, i: int, end: int) -> int:
    # by-ref arg check glue between INIT and the SENDs (normally skipped
    # inside collect_call; this is the walk-landed-anywhere fallback)
    ctx.bk(i)
    return i + 1
