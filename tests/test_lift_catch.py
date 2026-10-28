"""`emit_try` catch-clause namespacing (production regression).

The catch class was taken from the quote-escaped string form, leaving doubled
backslashes — `catch (A\\B\\C)` — which is a parse error in the lifted PHP.
The class must be resolved as a bare name, as INSTANCEOF already does.

Synthetic LiftContext fixtures so this runs without the research workspace.
"""

from ioncube_re.lift.model import LiftContext
from ioncube_re.lift.structurer import emit_try


def mk(nodes, zvals=None, cv=None):
    ns = []
    for k, (op, ent) in enumerate(nodes):
        ns.append({"i": k, "trueop": op, "final": op, "ext": 0, "lineno": 0,
                   "ent": ent, "op1": 0, "op2": 0, "res": 0})
    r = {"nodes": ns, "zvals": zvals or [], "thr": len(ns), "hdr": bytes(0x60),
         "fnrec": None, "pool": b""}
    return LiftContext.build(b"", r, {"cv": cv or {}})


def test_catch_class_is_not_backslash_doubled():
    # h=1 is the CATCH node; catchEntry == h-1 == 0
    ctx = mk([(54, {}), (42, {"op1": (1, 0), "res": (8, 0)})],
             zvals=[{"type": 6, "str": b"Vendor\\Client"}], cv={0: "e"})
    ctx.tryBlocks = [(0, 1)]
    ctx.jt[0] = 2
    emit_try(ctx, 0, (0, 1))
    text = "".join(ctx.out)
    assert "catch (Vendor\\Client $e)" in text
    assert "Vendor\\\\Client" not in text


def test_catch_falls_back_to_rendered_form_without_zval():
    ctx = mk([(54, {}), (42, {"op1": (8, 3), "res": (8, 0)})], cv={0: "e"})
    ctx.tryBlocks = [(0, 1)]
    ctx.jt[0] = 2
    emit_try(ctx, 0, (0, 1))
    assert "catch (" in "".join(ctx.out)
