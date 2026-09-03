"""Array-literal families: ADD_ARRAY_ELEMENT continuation (the collectArray
run's statement-level tail), ADD_ARRAY_UNPACK, the specialized IN_ARRAY.

Semantics ported from dawwinci/ioncube-php8-decompiler (MIT License,
Copyright (c) 2026 dawwinci, commit 2f2f35c) — decompiler/handlers/
arrays.py:22-53 — see notes/HANDLERS-PORT.md §1.
"""

from __future__ import annotations

from ..model import LiftContext
from ..registry import opcode_handler


def _slot(n) -> int | None:
    """The res temp slot of a node, or None when the result is unused."""
    e = n.ent.get("res")
    return n.res // 16 if e and (e.kind & 6) else None


def _array_item(ctx: LiftContext, n) -> str:
    r = ctx.render
    v = r.ch(r.ex_op1(n))
    k = None
    e = n.ent.get("op2")
    if e and e.kind != 0:
        k = r.ex(n, "op2")
    if k is not None and k not in ("0", "null"):
        return k + " => " + v
    return v


@opcode_handler(72)  # ADD_ARRAY_ELEMENT (dawwinci arrays.py:22-33)
def _add_array_element(ctx: LiftContext, i: int, end: int) -> int:
    # collect_array consumes the contiguous run; when a construct starter
    # (nested call) interrupted it, the run continues here: the res slot
    # holds the partial literal — extend it. Same slot: ionCube reuses the
    # INIT_ARRAY res slot for the whole construction.
    n = ctx.nodes[i]
    item = _array_item(ctx, n)
    slot = _slot(n)
    prev = ctx.tempExpr.get(slot) if slot is not None else None
    if prev is not None and prev.startswith("[") and prev.endswith("]"):
        ctx.tempExpr[slot] = prev[:-1] + (", " if len(prev) > 2 else "") + item + "]"
    else:
        # no live array temp (dawwinci's "without live array temp" fallback)
        if slot is not None:
            ctx.tempExpr[slot] = "[" + item + "]"
    ctx.emitted += 1
    return i + 1


@opcode_handler(147)  # ADD_ARRAY_UNPACK (dawwinci arrays.py:36-43)
def _add_array_unpack(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    item = "..." + ctx.render.ch(ctx.render.ex_op1(n))
    slot = _slot(n)
    prev = ctx.tempExpr.get(slot) if slot is not None else None
    if prev is not None and prev.startswith("[") and prev.endswith("]"):
        ctx.tempExpr[slot] = prev[:-1] + (", " if len(prev) > 2 else "") + item + "]"
    elif slot is not None:
        ctx.tempExpr[slot] = "[" + item + "]"
    ctx.emitted += 1
    return i + 1


@opcode_handler(187)  # IN_ARRAY (dawwinci arrays.py:46-53)
def _in_array(ctx: LiftContext, i: int, end: int) -> int:
    # the real specialized in_array (res temp, haystack expression); the
    # switch-header garble (res unused + const jumptable op2) was rewritten
    # to 185/186 in the constructor, so only real calls arrive here
    n = ctx.nodes[i]
    r = ctx.render
    args = [r.ch(r.ex_op1(n)), r.ch(r.ex_op2(n))]
    if n.ext & 1:
        args.append("true")
    return ctx.def_temp(n, "in_array(" + ", ".join(args) + ")", i)
