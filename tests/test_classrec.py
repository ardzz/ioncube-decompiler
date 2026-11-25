"""Class-record rendering: nullable types and the eval class skeleton."""

from ioncube_re.lift.classrec import prop_declare, prop_type
from ioncube_re.lift.pipeline import _declared_class


def test_prop_type_nullable_union_is_valid_php():
    assert prop_type(0x12, None) == "?int"
    # `?int|float` is a parse error; a nullable union is `int|float|null`
    assert prop_type(0x32, None) == "int|float|null"


def test_null_defaulted_typed_property_becomes_nullable():
    p = {"name": "ext", "vis": 4, "mask": 0x10, "class": None, "default": None}
    assert prop_declare(p) == "    private ?int $ext = null;"


def test_readonly_requires_a_type_and_no_default():
    # untyped + default: emitting readonly here is a PHP fatal
    p = {"name": "helper", "vis": 0x24, "mask": 0, "class": None, "default": None}
    assert prop_declare(p) == "    private $helper = null;"
    # typed, no default: keep the modifier
    p = {
        "name": "x",
        "vis": 0x24,
        "mask": 0x10,
        "class": None,
        "default": "__nodefault__",
    }
    assert prop_declare(p) == "    private readonly int $x;"


def test_declared_class_reads_declare_class_operands():
    r = {
        "nodes": [
            {"i": 0, "final": 62, "trueop": None, "ent": {"op1": (1, 1)}},
            {
                "i": 1,
                "final": 144,  # DECLARE_CLASS
                "trueop": None,
                "ent": {"op1": (1, 1), "op2": (1, 0)},
            },
        ],
        "zvals": [
            {"str": b"base_helper"},
            {"str": b"vendor\\pkg\\widget"},
        ],
    }
    assert _declared_class(r) == ("vendor\\pkg\\widget", "base_helper")


def test_declared_class_absent():
    assert _declared_class({"nodes": [], "zvals": []}) is None
