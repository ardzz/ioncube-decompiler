"""`Render.obj` bare-`new` parenthesisation (production regression).

`new X()->m()` only parses on PHP >= 8.4 (before that it means
`new (X()->m())`); recovered source must run in place on 8.2/8.3, so a bare
`new` receiver is wrapped as `(new X())->m()`.
"""

from ioncube_re.lift.model import LiftContext


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
