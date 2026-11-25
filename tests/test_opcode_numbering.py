"""The wire's official PHP 8.1/8.2 opcode numbers are mapped to the
loader-internal table before lift handlers run."""

from ioncube_re.lift import LiftContext, emit_node
from ioncube_re.opcodes import wire_to_internal


def mk_wire(nodes, zvals=None, cv=None):
    """A minimal LiftContext over wire-numbered finals (trueop=None)."""
    zvals = zvals or []
    ns = []
    for k, (final, ent, slots, ext) in enumerate(nodes):
        for w in ("op1", "op2", "res"):
            if w in ent:
                slots.setdefault(w, 0)
        ns.append(
            {
                "i": k,
                "trueop": None,
                "final": final,
                "ext": ext or 0,
                "lineno": 0,
                "ent": ent,
                **slots,
            }
        )
    hdr = bytearray(0x60)
    r = {
        "nodes": ns,
        "zvals": zvals,
        "thr": len(ns),
        "hdr": bytes(hdr),
        "fnrec": None,
        "pool": b"",
    }
    return LiftContext.build(b"", r, {"cv": cv or {}})


def test_official_wire_tail_maps_to_the_internal_table():
    assert wire_to_internal(42) == 42
    assert wire_to_internal(177) == 173  # FETCH_STATIC_PROP_FUNC_ARG
    assert wire_to_internal(178) == 177  # FETCH_STATIC_PROP_UNSET
    assert wire_to_internal(180) == 176  # ISSET_ISEMPTY_STATIC_PROP
    assert wire_to_internal(181) == 179  # FETCH_CLASS_CONSTANT
    assert wire_to_internal(184) == 182  # FETCH_THIS
    assert wire_to_internal(185) == 183  # SEND_FUNC_ARG
    assert wire_to_internal(187) == 185  # SWITCH_LONG
    assert wire_to_internal(188) == 186  # SWITCH_STRING
    assert wire_to_internal(190) == 188  # COUNT
    assert wire_to_internal(193) == 191  # GET_TYPE
    assert wire_to_internal(194) == 192  # ARRAY_KEY_EXISTS
    assert wire_to_internal(195) == 193  # MATCH
    assert wire_to_internal(196) == 194  # CASE_STRICT
    assert wire_to_internal(198) == 196  # JMP_NULL
    assert wire_to_internal(199) == 197  # CHECK_UNDEF_ARGS
    assert wire_to_internal(201) == 199  # VERIFY_NEVER_TYPE
    assert wire_to_internal(202) == 200  # CALLABLE_CONVERT


def test_count_uses_the_wire_number():
    l = mk_wire(
        [(190, {"op1": (8, 0), "res": (2, 0)}, {"res": 8 * 16}, 0)],
        cv={0: "x"},
    )
    assert l.op[0] == 188
    emit_node(l, 0, l.thr)
    assert l.tempExpr[8] == "count($x)"


def test_verify_never_tail_is_handled():
    l = mk_wire([(201, {}, {}, 0)])
    assert l.op[0] == 199
    emit_node(l, 0, l.thr)
    assert "opcode 201" not in "".join(l.out)


def test_fetch_class_constant_uses_the_wire_number():
    l = mk_wire(
        [(181, {"op1": (1, 0), "op2": (1, 1), "res": (2, 0)}, {"res": 8 * 16}, 0)],
        zvals=[
            {"type": 6, "str": b"PDO"},
            {"type": 6, "str": b"FETCH_ASSOC"},
        ],
    )
    assert l.op[0] == 179
    emit_node(l, 0, l.thr)
    assert l.tempExpr[8] == "\\PDO::FETCH_ASSOC"


def test_fetch_class_constant_qualifies_a_namespaced_class():
    l = mk_wire(
        [(181, {"op1": (1, 0), "op2": (1, 1), "res": (2, 0)}, {"res": 8 * 16}, 0)],
        zvals=[
            {"type": 6, "str": b"Symfony\\Component\\Console\\Input\\InputOption"},
            {"type": 6, "str": b"VALUE_REQUIRED"},
        ],
    )
    emit_node(l, 0, l.thr)
    assert (
        l.tempExpr[8]
        == "\\Symfony\\Component\\Console\\Input\\InputOption::VALUE_REQUIRED"
    )


def test_array_key_exists_uses_the_wire_number():
    l = mk_wire(
        [
            (
                194,
                {"op1": (8, 0), "op2": (8, 1), "res": (2, 0)},
                {"res": 8 * 16},
                0,
            )
        ],
        cv={0: "key", 1: "arr"},
    )
    assert l.op[0] == 192
    emit_node(l, 0, l.thr)
    assert l.tempExpr[8] == "array_key_exists($key, $arr)"


def test_fetch_class_name_renders_get_class():
    l = mk_wire(
        [(157, {"op1": (8, 0), "res": (2, 0)}, {"res": 8 * 16}, 0)],
        cv={0: "x"},
    )
    assert l.op[0] == 157
    emit_node(l, 0, l.thr)
    assert l.tempExpr[8] == "get_class($x)"


def test_direct_match_table_becomes_a_switch():
    table = (
        b"\x81[6'modulei1;4;4294967295;"
        b"9'componenti1;4;4294967295;}0;775;0;1;7;"
    )
    l = mk_wire(
        [
            (195, {"op1": (8, 0), "op2": (1, 0)}, {}, 0),  # MATCH
            (31, {"op1": (1, 1), "res": (2, 0)}, {"res": 6 * 16}, 0),
            (42, {"op1": (0, 6)}, {}, 0),
            (31, {"op1": (1, 2), "res": (2, 0)}, {"res": 6 * 16}, 0),
            (42, {"op1": (0, 6)}, {}, 0),
            (70, {"op1": (8, 0)}, {}, 0),
            (62, {"op1": (2, 0)}, {"op1": 6 * 16}, 0),
        ],
        zvals=[
            {"type": 7, "str": table},
            {"type": 6, "str": b"yes"},
            {"type": 6, "str": b"no"},
        ],
        cv={0: "x"},
    )
    assert l.op[0] == 193
    emit_node(l, 0, l.thr)
    text = "".join(l.out)
    assert "switch (true)" in text
    assert "case ($x) === 'module':" in text
    assert "case ($x) === 'component':" in text
    assert "return 'yes';" in text
    assert "return 'no';" in text
    assert "break;" in text
    assert "default:" in text
    assert "$T1" not in text
