"""The opcode dispatch registry (OCP: a new opcode family is a new entry in
``HANDLERS`` — registered from a handlers/ family module, zero core edits).

The handler contract is the one fixed by the item-2 port (notes/
HANDLERS-PORT.md §1, 28 tests): ``Handler = Callable[[LiftContext, int, int],
int]`` — run the node at index ``i`` inside region end ``end`` and return the
next node index (multi-node families such as ASSIGN_OBJ + OP_DATA or the call
collectors return ``i + 2`` / the DO successor). Statement families write
their lines through the context; expression families store a string into the
node's res temp slot via ``ctx.def_temp`` so the value renders at its single
use site. Unknown opcodes simply have no entry — the emitter degrades them
to the structured comment (graceful degradation is the registry's contract).

(A ``Callable[[Node, LiftContext], str|None]`` shape was considered and
rejected: statement families must consume successor nodes and emit directly,
so a pure-expression signature would force a second dispatch tier for them —
more machinery, zero behavior gain. Documented in notes/REFACTOR.md.)
"""

from __future__ import annotations

from typing import Callable

#: handler(ctx: LiftContext, i: int, end: int) -> next node index
Handler = Callable[..., int]

#: opcode number -> handler
HANDLERS: dict[int, Handler] = {}


def opcode_handler(*ops: int) -> Callable[[Handler], Handler]:
    def register(func: Handler) -> Handler:
        for op in ops:
            if op in HANDLERS:
                raise ValueError(f"duplicate handler for opcode {op}")
            HANDLERS[op] = func
        return func

    return register


__all__ = ["HANDLERS", "Handler", "opcode_handler"]
