"""The opcode family modules — each registers its opcodes into the registry
(handlers are one module per FAMILY, notes/REFACTOR.md's SRP mapping).

Importing this package registers every family; the re-exports keep the
pre-refactor import surface (`from ioncube_re.lift.handlers import HANDLERS`)
working.
"""

from ..registry import HANDLERS, Handler, opcode_handler  # noqa: F401

from . import arithmetic, arrays, calls, control, misc, objects, variables  # noqa: F401,E402

__all__ = ["HANDLERS", "Handler", "opcode_handler"]
