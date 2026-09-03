"""The component walk: emit_region/emit_node — the one dispatcher every
statement goes through — and the per-component lift entry (accounting
footer included). No family logic lives here: control flow delegates to
structurer/loops, expressions to the collectors, opcode families to the
handlers/ package via the registry.

Importing :mod:`ioncube_re.lift.handlers` (below) triggers every family
module's registrations — that is the only wiring this module does.
"""

from __future__ import annotations

from . import handlers  # noqa: F401 — imports register the opcode families
from . import loops, structurer
from .model import LiftContext
from .registry import HANDLERS


def walk_component(ctx: LiftContext) -> str:
    """Lift one component: the full statement walk + the accounting footer
    (E+B+M+U; the display-level drift vs thr is documented in
    HANDLERS-PORT.md §4 — no node is dropped or double-rendered in text)."""
    emit_region(ctx, 0, ctx.thr)
    ctx.w(f"/* {ctx.thr} nodes: {ctx.emitted} emitted, {ctx.bookkept} "
          f"bookkeeping/param, {ctx.masked} masked, {ctx.unknown} unknown */")
    return "".join(ctx.out)


def emit_region(ctx: LiftContext, i: int, end: int) -> None:
    while i < end:
        nx = emit_node(ctx, i, end)
        if nx <= i:  # structural guard: never stall
            ctx.w(f"/* n{i}: stalled (target inside self) — guard */")
            nx = i + 1
        i = nx


def emit_node(ctx: LiftContext, i: int, end: int) -> int:
    # --valid-php: a label for every registered goto target, at its node
    if ctx.valid_php and i in ctx.goto_targets and i not in ctx.labels_emitted:
        ctx.labels_emitted.add(i)
        ctx.w(f"label_{i}:")
    for tb in ctx.tryBlocks:
        if tb[0] == i:
            return structurer.emit_try(ctx, i, tb)
    # (Part C) do-while: a conditional back-edge to this node, by fallthrough
    dw = loops.do_while_at(ctx, i, end)
    if dw is not None:
        return dw
    n = ctx.nodes[i]
    op = ctx.op[i]
    if op is None:
        ctx.line(n)
        ctx.w(f"/* n{i}: opcode masked (no arena/ktab) op1={ctx.render.opnd_text(n, 'op1')} "
              f"op2={ctx.render.opnd_text(n, 'op2')} res={ctx.render.opnd_text(n, 'res')} */")
        return i + 1
    h = HANDLERS.get(op)
    if h is not None:
        return h(ctx, i, end)
    # unknown opcode -> structured comment (graceful degradation)
    from ..opcodes import OPNAMES

    ctx.line(n)
    nm = OPNAMES.get(op, f"op{op}")
    ctx.w(f"/* {nm} (opcode {op}) op1={ctx.render.opnd_text(n, 'op1')} "
          f"op2={ctx.render.opnd_text(n, 'op2')} res={ctx.render.opnd_text(n, 'res')} */")
    ctx.unknown += 1
    return i + 1


__all__ = ["emit_node", "emit_region", "walk_component"]
