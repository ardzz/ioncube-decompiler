"""The lift layer: oplines -> readable PHP source (the ic_lift port and
the port-queue items 2-4, notes/PYTHON-PORT.md / HANDLERS-PORT.md /
DAWWINCI-DIFF.md §5)."""

from .emitter import emit_node, emit_region, walk_component
from .model import Component, LoopInfo, LiftContext, Node, Operand
from .pipeline import PipelineError, lift_file
from .registry import HANDLERS, Handler, opcode_handler

__all__ = ["Component", "Handler", "HANDLERS", "LoopInfo", "LiftContext",
           "Node", "Operand", "PipelineError", "emit_node", "emit_region",
           "lift_file", "opcode_handler", "walk_component"]
