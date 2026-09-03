"""Per-family handler unit tests — one section per handlers/ module
(arithmetic, variables, objects, misc), the synthetic-fixture layer the
refactor contract asks for. The arrays/calls/control families are covered
by test_handlers.py (the item-2 port tests) and test_structurer.py (the
item-3/4 patterns) respectively.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from ioncube_re.lift import LiftContext, emit_node

UNUSED = (0, 0xFFFFFFFF)


def mk(nodes, zvals=None, cv=None, thr=None):
    """A minimal LiftContext over synthetic nodes (the test_handlers shape)."""
    zvals = zvals or []
    ns = []
    for k, (op, ent, slots, ext) in enumerate(nodes):
        for w in ("op1", "op2", "res"):
            if w in ent:
                slots.setdefault(w, 0)
        ns.append({"i": k, "trueop": op, "final": op, "ext": ext or 0,
                   "lineno": 0, "ent": ent, **slots})
    hdr = bytearray(0x60)
    r = {"nodes": ns, "zvals": zvals, "thr": thr or len(ns),
         "hdr": bytes(hdr), "fnrec": None, "pool": b""}
    return LiftContext.build(b"", r, {"cv": cv or {}})


def out(ctx):
    return "".join(ctx.out)


# ---- handlers/arithmetic.py ----


def test_arith_binop_parens():
    l = mk([(1, {"op1": (8, 0), "op2": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 4, "a": 2}], cv={0: "a"})
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "($a + 2)"


def test_arith_concat_no_defensive_parens():
    l = mk([(8, {"op1": (1, 0), "op2": (8, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 6, "str": b"hi "}], cv={0: "who"})
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "'hi ' . $who"


def test_arith_unary_and_cast():
    l = mk([(14, {"op1": (8, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
            (51, {"op1": (8, 0), "res": (2, 0)}, {"res": 8 * 16}, 3)],
           cv={0: "x"})
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "!($x)"
    emit_node(l, 1, l.thr)
    assert l.tempExpr[8] == "(is_long)($x)"  # ext 3 = is_long (cast_name map)


def test_arith_type_check():
    l = mk([(123, {"op1": (8, 0), "res": (2, 0)}, {"res": 7 * 16}, 3)], cv={0: "x"})
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "is_long($x)"


def test_arith_coalesce_instanceof_fn1():
    l = mk([(169, {"op1": (8, 0), "op2": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
            (138, {"op1": (8, 0), "op2": (1, 1), "res": (2, 0)}, {"res": 8 * 16}, 0),
            (121, {"op1": (8, 0), "res": (2, 0)}, {"res": 9 * 16}, 0)],
           zvals=[{"type": 1}, {"type": 6, "str": b"Exception"}], cv={0: "x"})
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "$x ?? null"
    emit_node(l, 1, l.thr)
    assert l.tempExpr[8] == "$x instanceof Exception"
    emit_node(l, 2, l.thr)
    assert l.tempExpr[9] == "strlen($x)"


def test_arith_qm_assign_passthrough():
    l = mk([(31, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 6, "str": b"v"}])
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "'v'"


# ---- handlers/variables.py ----


def test_assign_statement_and_res_temp():
    l = mk([(22, {"op1": (8, 0), "op2": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 4, "a": 5}], cv={0: "x"})
    emit_node(l, 0, l.thr)
    assert "$x = 5;" in out(l)
    assert l.tempExpr[7] == "5"


def test_incdec_forms():
    l = mk([(34, {"op1": (8, 0)}, {}, 0), (36, {"op1": (8, 0)}, {}, 0)], cv={0: "i"})
    emit_node(l, 0, l.thr)
    emit_node(l, 1, l.thr)
    t = out(l)
    assert "++$i;" in t and "$i++;" in t


def test_fetch_r_superglobal_vs_globals():
    # interned-name zval resolves _GET -> bare $_GET; other names -> $GLOBALS
    from ioncube_re.lift.operand import zval_name
    zv = {"type": 6, "str": b"_GET"}
    l = mk([(80, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
            (80, {"op1": (1, 1), "res": (2, 0)}, {"res": 8 * 16}, 0)],
           zvals=[zv, {"type": 6, "str": b"registry"}])
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "$_GET"
    emit_node(l, 1, l.thr)
    assert l.tempExpr[8] == "$GLOBALS['registry']"  # symbol-table key: quoted (ic_lift parity)


def test_fetch_constant_bare_reference():
    l = mk([(99, {"op2": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 6, "str": b"Blesta\\App\\Models\\DS"}])
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "\\Blesta\\App\\Models\\DS"


def test_rope_interpolation_chain():
    l = mk([
        (54, {"op2": (1, 0)}, {}, 0),                 # ROPE_INIT 'a'
        (55, {"op2": (8, 0)}, {}, 0),                 # ROPE_ADD $v
        (56, {"op2": (1, 1), "res": (2, 0)}, {"res": 7 * 16}, 0),  # ROPE_END 'b'
    ], zvals=[{"type": 6, "str": b"a"}, {"type": 6, "str": b"b"}], cv={0: "v"})
    for k in range(l.thr):
        emit_node(l, k, l.thr)
    assert l.tempExpr[7] == "'a' . $v . 'b'"


def test_isset_empty_families():
    l = mk([(114, {"op1": (8, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
            (114, {"op1": (8, 1), "res": (2, 0)}, {"res": 8 * 16}, 2)],
           cv={0: "x", 1: "y"})
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "isset($x)"
    emit_node(l, 1, l.thr)
    assert l.tempExpr[8] == "empty($y)"


def test_unset_var_and_bind_global():
    l = mk([(74, {"op1": (8, 0)}, {}, 0), (168, {"op2": (8, 1)}, {}, 0)],
           cv={0: "x", 1: "g"})
    emit_node(l, 0, l.thr)
    emit_node(l, 1, l.thr)
    t = out(l)
    assert "unset($x);" in t and "global $g;" in t


# ---- handlers/objects.py ----


def test_fetch_obj_this_receiver():
    l = mk([(82, {"op1": (0, 0), "op2": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 6, "str": b"name"}])
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "$this->name"


def test_fetch_dim():
    l = mk([(81, {"op1": (8, 0), "op2": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 4, "a": 3}], cv={0: "row"})
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "$row[3]"


def test_pre_inc_obj_and_isset_prop():
    l = mk([(132, {"op1": (0, 0), "op2": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
            (148, {"op1": (0, 0), "op2": (1, 0), "res": (2, 0)}, {"res": 8 * 16}, 2)],
           zvals=[{"type": 6, "str": b"count"}])
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "++$this->count"
    emit_node(l, 1, l.thr)
    assert l.tempExpr[8] == "empty($this->count)"


# ---- handlers/misc.py ----


def test_echo_throw_exit_include():
    l = mk([(136, {"op1": (1, 0)}, {}, 0),
            (108, {"op1": (1, 1)}, {}, 0),
            (79, {"op1": (1, 0)}, {}, 0),
            (73, {"op1": (1, 2)}, {}, 8)],
           zvals=[{"type": 4, "a": 1}, {"type": 6, "str": b"Ex"},
                  {"type": 6, "str": b"lib.php"}])
    for k in range(l.thr):
        emit_node(l, k, l.thr)
    t = out(l)
    assert "echo 1;" in t
    assert "throw 'Ex';" in t
    assert "exit(1);" in t
    assert "require 'lib.php';" in t


def test_bookkeeping_set_counts_once():
    ops = [0, 63, 64, 70, 101, 102, 103, 104, 105, 107, 109, 124, 127, 137, 164]
    l = mk([(op, {}, {}, 0) for op in ops])
    for k in range(l.thr):
        emit_node(l, k, l.thr)
    assert l.bookkept == len(ops)
    assert l.unknown == 0
    assert out(l) == ""


def test_declare_comment_form():
    l = mk([(144, {"op1": (1, 0), "op2": (1, 1)}, {}, 0)],
           zvals=[{"type": 6, "str": b"m"}, {"type": 6, "str": b"p"}])
    emit_node(l, 0, l.thr)
    assert "/* DECLARE_CLASS op1=string('m') op2=string('p') */" in out(l)


# ---- registry shape over the family modules ----


def test_every_family_module_is_registered():
    from ioncube_re.lift.registry import HANDLERS
    from ioncube_re.lift import handlers

    assert handlers.arithmetic and handlers.variables and handlers.objects
    assert handlers.arrays and handlers.calls and handlers.control and handlers.misc
    # one entry per opcode, no overlaps (the decorator enforces it); spot
    # the family boundaries
    for op in (1, 8, 31, 51, 123, 169):        # arithmetic
        assert op in HANDLERS
    for op in (22, 25, 26, 54, 74, 80, 99, 114, 168):  # variables
        assert op in HANDLERS
    for op in (76, 81, 82, 97, 132, 148, 182):  # objects
        assert op in (HANDLERS)
    for op in (72, 147, 187):                    # arrays
        assert op in HANDLERS
    for op in (59, 68, 71, 100, 183):            # calls
        assert op in HANDLERS
    for op in (42, 43, 48, 62, 77, 152, 185):    # control
        assert op in HANDLERS
    for op in (136, 141, 57, 58, 142, 181):      # misc
        assert op in HANDLERS
    # the unknown fallback stays: no handlers for these
    for op in (193, 196, 50, 66):
        assert op not in HANDLERS
