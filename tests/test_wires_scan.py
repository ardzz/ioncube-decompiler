"""Sub-wire discovery regressions (production ICB0 wires).

Two ways `scan_wires` used to drop whole functions:

1. it keyed discovery on the exact header word `02 00 00 00`, but the header's
   first word is [type|flags] and real functions carry flag bits in the upper
   bytes (`02 00 00 01`, `02 01 00 00`, `02 10 00 00` all occur);
2. it required `parse_end == declared_record_size`, but a record may declare a
   size that covers a trailing nested-record region (nested closure wires),
   so the wire ends before the declared size.

Synthetic wires are built directly from the header grammar so these run
without the external research workspace.
"""

import struct

from ioncube_re.container import u32
from ioncube_re.lift.wires import _magic, _plausible, scan_wires
from ioncube_re.wire import parse_wire


def p32(v):
    return struct.pack("<I", v)


def make_wire(magic=b"\x02\x00\x00\x00", thr=1):
    """A minimal valid wire: empty statics/keys/tables, `thr` no-op sig nodes."""
    hdr = bytearray(0x7C)
    hdr[0:4] = magic
    hdr[0x14:0x18] = p32(0)  # num_args
    hdr[0x30:0x34] = p32(thr)  # thr
    w = bytearray(hdr) + bytearray(4)  # checksum placeholder
    s1 = s2 = 0
    for c in w[:0x7C]:
        s1 = (s1 + c) & 0xFF
        s2 = (s2 + s1) & 0xFF
    w[0x7C:0x7E] = struct.pack("<H", (s1 | (s2 << 8)) & 0xFFFF)
    w += p32(0)  # local_140
    w += p32(0)  # statics count
    w += p32(0)  # fn-info count
    w += p32(0)  # keytable count
    w += p32(2 * thr)  # op count (sig mode: 2 words per node)
    for _ in range(2 * thr):
        w += p32(1)
    w += p32(0)  # entry count
    w += p32(0)  # -> opa+0x38
    w += p32(0)  # pool size
    return bytes(w)


# ---- header magic (bug 1) ----


def test_magic_accepts_flag_variants():
    for magic in (b"\x02\x00\x00\x00", b"\x02\x00\x00\x01", b"\x02\x01\x00\x00", b"\x02\x10\x00\x00"):
        assert _magic(magic), magic.hex()


def test_magic_rejects_other_words():
    assert not _magic(b"\x03\x00\x00\x00")  # wrong marker byte
    assert not _magic(b"\x02\x00\x00\x40")  # implausibly high flag byte
    assert not _magic(b"\x02\x00")


def test_scan_finds_flagged_magic_wire():
    wire = make_wire(b"\x02\x10\x00\x00")
    stream = p32(len(wire)) + wire
    found = scan_wires(stream, 0)
    assert len(found) == 1
    off, size, r = found[0]
    assert (off, size) == (4, len(wire))
    assert r["chk"] and r["thr"] == 1


# ---- record size with a trailing nested-record region (bug 2) ----


def test_scan_returns_wire_end_for_record_with_tail():
    tail = b"\x00" * 24  # a nested-record region without its own outer magic
    wire = make_wire()
    declared = len(wire) + len(tail)
    stream = p32(declared) + wire + tail
    found = scan_wires(stream, 0)
    assert len(found) == 1
    off, size, _ = found[0]
    assert off == 4
    assert size == len(wire)  # wire end, not the declared record size
    assert u32(stream, off - 4) == declared


def test_scan_finds_wire_after_a_tail_record():
    tail = b"\x00" * 24
    a = make_wire()
    b = make_wire()
    stream = p32(len(a) + len(tail)) + a + tail + p32(len(b)) + b
    found = scan_wires(stream, 0)
    assert [size for _, size, _ in found] == [len(a), len(b)]


def test_plausible_rejects_bad_prefix_and_checksum():
    wire = make_wire()
    assert _plausible(wire)
    assert not _plausible(wire[:0x80])  # too short
    bad = bytearray(make_wire())
    bad[0x7C] ^= 0xFF  # break the checksum
    assert not _plausible(bytes(bad))
    assert not _plausible(b"\x09" + make_wire()[1:])
    # the synthetic wire really is parseable
    assert parse_wire(wire)["end"] == len(wire)
