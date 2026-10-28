"""Regression tests for the corpus-validity batch (follow-up fixes):
try/catch starting at node 0, bool type masks, the suppressed duplicate
epilogue return, the shifted op-run probe, and serialized const-fetch
defaults."""

import struct

from ioncube_re.lift.signature import render_type
from ioncube_re.lift.structurer import _jmp_return
from ioncube_re.lift.analysis import _tc_records
from ioncube_re.lift.model import LiftContext
from ioncube_re.lift.operand import zval_php
from ioncube_re.wire import parse_wire


def p32(v):
    return struct.pack("<I", v)


# ---- try/catch record starting at node 0 ----


def make_ctx(thr=3):
    """A bare LiftContext over `thr` no-op sig nodes (no wire parse)."""
    ctx = LiftContext.__new__(LiftContext)
    return ctx


def test_tc_records_keep_node_zero():
    """A function without a RECV/HANDLE_EXCEPTION prologue starts its try
    region at node 0; the record must survive `_tc_records`."""
    # build a minimal wire with one tc record (0 -> 2)
    hdr = bytearray(0x7C)
    hdr[0x30:0x34] = p32(3)  # thr
    hdr[0x50:0x54] = p32(1)  # tc count
    w = bytearray(hdr) + bytearray(4) + p32(0)  # checksum, opa+0x40
    w += p32(0)  # the count word preceding the tc records
    w += p32(0) + p32(2) + p32(0) + p32(0)  # tc record: (start=0, handler=2)
    ctx = make_ctx()
    ctx.wire = bytes(w)
    ctx.r = {"hdr": bytes(hdr)}
    ctx.thr = 3
    assert _tc_records(ctx) == [(0, 2)]


# ---- render_type bool masks ----


def test_render_type_bool_masks():
    assert render_type(0x4 | 0x8) == "bool"  # false|true
    assert render_type(0x2 | 0x4 | 0x8) == "?bool"  # null|false|true
    assert render_type(0x2 | 0x40) == "?string"  # null|string


# ---- bare return after an inlined value return ----


def test_jmp_return_skips_duplicate_epilogue():
    """After `return X;` the unreachable VERIFY+RETURN epilogue must not
    emit a second bare return (fatal in a typed function)."""

    class N:
        def __init__(s, ent):
            s.ent = ent
            s.i = 0

    ctx = make_ctx()
    ctx.nodes = [N({}), N({})]
    ctx.out = ["return 14 - $age;\n"]
    ctx.meta = {}
    ctx.render = type("R", (), {"ex_op1": staticmethod(lambda n: None)})()
    nxt = _jmp_return(ctx, 0, 1, 1, 2, "epilogue")
    assert nxt == 1
    assert ctx.out == ["return 14 - $age;\n"]


def test_jmp_return_emits_typed_null_without_prior_return():
    class N:
        def __init__(s, ent):
            s.ent = ent
            s.i = 0

    ctx = make_ctx()
    ctx.nodes = [N({}), N({})]
    ctx.out = []
    ctx.meta = {"hasRetType": True}
    ctx.render = type("R", (), {"ex_op1": staticmethod(lambda n: None)})()
    ctx.line = lambda n: None
    ctx.w = lambda s: ctx.out.append(s)
    ctx.emitted = 0
    _jmp_return(ctx, 0, 1, 1, 2, "epilogue")
    assert ctx.out == ["return null; /*epilogue */"]


# ---- shifted op-run probe ----


def test_parse_wire_shifted_opcnt():
    """One extra prologue word before the op count: the probe must locate
    the real op-run (and keep the parse consuming the wire)."""
    hdr = bytearray(0x7C)
    hdr[0x30:0x34] = p32(1)  # thr
    w = bytearray(hdr) + bytearray(4)  # checksum placeholder
    s1 = s2 = 0
    for c in w[:0x7C]:
        s1 = (s1 + c) & 0xFF
        s2 = (s2 + s1) & 0xFF
    w[0x7C:0x7E] = struct.pack("<H", (s1 | (s2 << 8)) & 0xFFFF)
    w += p32(0)  # opa+0x40
    w += p32(0)  # statics
    w += p32(0)  # fn-info
    w += p32(0)  # keytable count <- fixed-offset readers stop here
    w += p32(0xDEAD)  # unmodeled prologue word shifts the op count
    w += p32(2)  # op count (sig: 2 words)
    w += p32(1) + p32(0)  # one sig node
    w += p32(0)  # entry count
    w += p32(0)  # -> opa+0x38
    w += p32(0)  # pool size
    r = parse_wire(bytes(w))
    assert r["thr"] == 1 and len(r["nodes"]) == 1


# ---- serialized const-fetch defaults ----


def test_zval_const_fetch_serarr():
    """A zval whose blob starts with the production 0x81 prefix and carries
    a `Cls::CONST` payload renders as a class-constant fetch."""
    z = {"type": 7, "str": b"\x81@:64:0;s3'Cls's4'NAME'"}
    out = zval_php(z, 0)
    assert "Cls::NAME" in out
