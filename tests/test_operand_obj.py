"""`Render.obj` bare-`new` parenthesisation (production regression).

`new X()->m()` only parses on PHP >= 8.4 (before that it means
`new (X()->m())`); recovered source must run in place on 8.2/8.3, so a bare
`new` receiver is wrapped as `(new X())->m()`.
"""

from ioncube_re.lift.model import LiftContext
from ioncube_re.lift.operand import class_ref, zval_php


def mk():
    r = {"nodes": [], "zvals": [], "thr": 0, "hdr": bytes(0x60),
         "fnrec": None, "pool": b""}
    return LiftContext.build(b"", r, {"cv": {}})


def test_obj_parenthesises_bare_new():
    ctx = mk()
    assert ctx.render.obj("new Foo()") == "(new Foo())"
    assert ctx.render.obj("new \\A\\B($x)") == "(new \\A\\B($x))"


def test_obj_leaves_safe_receivers_alone():
    ctx = mk()
    assert ctx.render.obj("$this") == "$this"
    assert ctx.render.obj("$x") == "$x"
    assert ctx.render.obj("foo") == "$foo"
    assert ctx.render.obj("$a->b") == "$a->b"


def test_class_ref_fully_qualifies_wire_names():
    # the wire stores resolved FQCNs; inside an emitted namespace they need
    # a leading backslash so they cannot resolve relative to it
    assert class_ref("Vendor\\Client") == "\\Vendor\\Client"
    assert class_ref("Exception") == "\\Exception"
    assert class_ref("\\Vendor\\Client") == "\\Vendor\\Client"


def test_class_ref_leaves_keywords_expressions_and_placeholders():
    for s in ("self", "parent", "static", "$cls", "(expr)",
              "self /*class-unresolved*/"):
        assert class_ref(s) == s


def test_zval_php_parses_00442_class_constant_record():
    # the 00442 generation tags the record @<n>:<n>:... instead of @:
    raw = (
        b"\x81@2054:517:512:2;@4528:64:1:0;s4'self262;431;1;22;"
        b"@3696:64:0:0;s15'EMAIL_TYPE_HTML262;0;1;22;267;0;2;27;"
    )
    assert zval_php({"type": 267, "str": raw}, 0) == "self::EMAIL_TYPE_HTML"
