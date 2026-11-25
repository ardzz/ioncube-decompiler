"""Tail docblock recovery (ionCube preserves declaration docblocks)."""

from ioncube_re.lift.wires import tail_doccomment

DOC = b"/**\n * A preserved class docblock.\n */"


def _carrier(doc: bytes) -> bytes:
    return b"\x00" * 8 + len(doc).to_bytes(2, "little") + b"\x00\x20" + doc


def test_tail_doccomment_extracts_the_docblock():
    assert tail_doccomment(_carrier(DOC), 0) == DOC.decode()


def test_tail_doccomment_absent_returns_none():
    assert tail_doccomment(b"\x00" * 32, 0) is None
