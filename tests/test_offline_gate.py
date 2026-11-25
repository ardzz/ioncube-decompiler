"""offline_parse's sig gate: sig-mode wires only.

Nosig (v<=5) components legally end in the exception epilogue
(HANDLE_EXCEPTION 149); applying the eval sig-mode RETURN-tail rule to them
false-negatives whole components (a 173-node component with every final in
range but ending in HANDLE_EXCEPTION).
"""

from ioncube_re.lift import sources


def _wire(thr: int) -> bytes:
    w = bytearray(0x40)
    w[0x30:0x34] = thr.to_bytes(4, "little")
    return bytes(w)


def _run(monkeypatch, mode, lastf, sig_gate=True):
    r = {"thr": 1, "nodes": [{"final": lastf, "sigok": True}], "mode": mode}
    monkeypatch.setattr(sources, "parse_wire", lambda *a, **k: r)
    monkeypatch.setattr(
        "ioncube_re.crypto.keytable.kt_generate", lambda *a, **k: b"\0" * 8
    )
    return sources.offline_parse(_wire(1), (1, 2), 3, 2, sig_gate)


def test_nosig_component_may_end_in_handle_exception(monkeypatch):
    assert _run(monkeypatch, "nosig", 149) is not None


def test_nosig_component_must_still_be_in_range(monkeypatch):
    assert _run(monkeypatch, "nosig", 0xFFFF) is None


def test_sig_gate_still_rejects_a_bad_tail(monkeypatch):
    assert _run(monkeypatch, "sig", 149) is None


def test_sig_gate_accepts_return_tail(monkeypatch):
    assert _run(monkeypatch, "sig", 62) is not None
