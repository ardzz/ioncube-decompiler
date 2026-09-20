"""Offline recovery of the eval encoder's wD0 (anti-tamper) opcodes.

For a node whose anti-tamper signature does NOT validate (sig mode, v>5),
the stored opcode byte is masked garbage; the true opcode comes from the
wD0 variant tables inside the ionCube loader .so (the Ghidra-decompiled
wD0 path at 0x1dcbf6):

    derived = k0 | k1<<8 | k2<<16 | (k0^k1)<<24     (k = ktab[thr+3i..])
    delta   = (derived ^ wire_sig) & 0xFFFF          (the encoder's overwrite)
    idx     = derived & 7
    tidx    = T1[variant][delta + idx*0x1000] ^ T2[variant][...]
    opcode  = the vmdef handler entry HANDLERS[tidx] (broadcast K1 already
              cancelled: the variant tables index the pre-mask table)

All inputs are file-derived except the loader binary itself (env override
IONCUBE_RE_LOADER). X (the variant selector) = mainblob u32@0x1c; X=2 on
every observed eval file; variants 0..6 exist symmetrically in the tables.
"""

from __future__ import annotations

import os
import struct

_HVA2OP: dict[int, int] | None = None
_TABLES: dict[int, tuple[bytes, bytes]] | None = None
_HANDLERS: tuple[int, ...] = ()


def _va2off(va: int) -> int:
    # the 8.1 loader's ET_DYN mapping used by the frozen m6 scripts
    return va - 0x440550 + 0x240550


def _ensure() -> None:
    global _HVA2OP, _TABLES, _HANDLERS
    if _HVA2OP is not None or _TABLES is not None:
        return
    roots = [
        os.environ.get("IONCUBE_RE_LOADER"),
        "/home/reky/workspaces/cylab/ioncube/loaders/ioncube/ioncube_loader_lin_8.1.so",
    ]
    so = None
    for p in roots:
        if p and os.path.isfile(p):
            try:
                with open(p, "rb") as f:
                    so = f.read()
                break
            except OSError:
                continue
    if so is None:
        _HVA2OP = {}
        _TABLES = {}
        return

    tt = struct.unpack_from("<16I", so, 0x206CA0)
    opmap = so[0x207120 : 0x207120 + 256]
    vm = struct.unpack_from("<256I", so, 0x206CE0)
    hoff = _va2off(0x440560)
    nh = 0
    while True:
        v = struct.unpack_from("<Q", so, hoff + 8 * nh)[0]
        if v == 0 or v > 0x2000000:
            break
        nh += 1
    handlers = struct.unpack_from(f"<{nh}Q", so, hoff)

    from ..opcodes import OPNAMES

    def kind(b: int) -> int:
        return tt[b & 0xF] if (b & 0xF) < 16 else 3

    hva2op: dict[int, int] = {}
    kinds = [0, 1, 2, 4]
    rts = [0, 2, 0x12, 0x22]
    for opnum in range(207):
        if opnum not in OPNAMES:
            continue
        ctrl = vm[opmap[opnum]]
        base = ctrl & 0xFFFF
        for k1 in kinds:
            for k2 in kinds:
                for rt in rts:
                    sp = 0
                    if ctrl & 0x10000:
                        sp = k1
                    if ctrl & 0x20000:
                        sp = sp * 5 + k2
                    if ctrl & 0x40000:
                        sp = sp * 5 + 3
                    if ctrl & 0x80000:
                        sp = (1 if rt else 0) + sp * 2
                    if ctrl & 0x200000:
                        sp = sp * 3 + (1 if rt == 0x12 else 2 if rt == 0x22 else 0)
                    for e in (0, 1):
                        sp2 = sp
                        if ctrl & 0x1000000:
                            sp2 = (e & 1) + sp2 * 2
                        if ctrl & 0x2000000:
                            sp2 = 1 + sp2 * 2
                        idx = base + sp2
                        if idx < nh:
                            hva2op.setdefault(handlers[idx] & 0xFFFFF, opnum)

    tables: dict[int, tuple[bytes, bytes]] = {}
    for v in range(7):
        a = (0x1F6CA0 - v * 0x10000, 0x186CA0 - v * 0x10000)
        t1 = so[a[0] : a[0] + 0x20000]
        t2 = so[a[1] : a[1] + 0x20000]
        if len(t1) == 0x20000 and len(t2) == 0x20000:
            tables[v] = (t1, t2)

    _HVA2OP = hva2op
    _TABLES = tables
    _HANDLERS = handlers


def resolve(sig: int, i: int, thr: int, kt: bytes, x: int = 2) -> int | None:
    """The true opcode of one wD0 node (sig mode, v>5), or None."""
    _ensure()
    if not _HVA2OP or not _TABLES:
        return None
    tables = _TABLES.get(x)
    if tables is None:
        return None
    if thr + 3 * i + 3 > len(kt):
        return None
    k0 = kt[thr + 3 * i]
    kb1 = kt[thr + 3 * i + 1]
    kb2 = kt[thr + 3 * i + 2]
    derived = k0 | (kb1 << 8) | (kb2 << 16) | ((k0 ^ kb1) << 24)
    delta = (derived ^ sig) & 0xFFFF
    off = (delta + (derived & 7) * 0x1000) * 2
    try:
        tidx = (
            struct.unpack_from("<H", tables[0], off)[0]
            ^ struct.unpack_from("<H", tables[1], off)[0]
        )
    except struct.error:
        return None
    if tidx >= len(_HANDLERS):
        return None
    return _HVA2OP.get(_HANDLERS[tidx] & 0xFFFFF)


__all__ = ["resolve"]
