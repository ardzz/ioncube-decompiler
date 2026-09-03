"""Opcode-source resolution: how each wire's opcodes get demasked — the m5
arena/ktab capture auto-discovery, the explicit capture pairs, and the
M6-KEYTAB offline keytable with its validation gate."""

from __future__ import annotations

import math
import os
from glob import glob

from ..container import u32
from ..wire import parse_wire


# ---- m5 auto-discovery (arena/ktab capture reuse) ----


def m5_sample_dir(wire: bytes, m5dir: str) -> str | None:
    if not m5dir or not os.path.isdir(m5dir):
        return None
    for f in sorted(glob(os.path.join(m5dir, "*", "readerA_*"))):
        if os.path.getsize(f) != len(wire):
            continue
        with open(f, "rb") as fh:
            if fh.read() == wire:
                return os.path.dirname(f)
    return None


def capture_pairs(dirs: list[str]) -> list[tuple[str, str]]:
    pairs = []
    for d in dirs:
        a = sorted(glob(os.path.join(d, "arena_*")))
        k = sorted(glob(os.path.join(d, "ktab_*")))
        for i in range(min(len(a), len(k))):
            pairs.append((a[i], k[i]))
    return pairs


def best_pair(wire: bytes, pairs: list[tuple[str, str]]) -> tuple[dict, str] | None:
    """Best (reparse, 'arena+ktab') for a wire; None unless convincing (>=60%
    trueops + at least one valid signature when the ktab carries sig keys)."""
    best = None
    best_score = -1
    thr = 0
    best_sig = 0
    best_true = 0
    best_sig_possible = False
    for pa, pk in pairs:
        with open(pa, "rb") as f:
            arena = f.read()
        with open(pk, "rb") as f:
            kt = f.read()
        try:
            r = parse_wire(wire, kt, arena)
        except Exception:
            continue
        if r["thr"] < 1:
            continue
        score = 0
        sig = 0
        tr = 0
        for n in r["nodes"]:
            if n["trueop"] is not None:
                score += 2
                tr += 1
            if n["sigok"]:
                score += 1
                sig += 1
        thr = r["thr"]
        if score > best_score:
            best_score = score
            best = (r, "arena+ktab")
            best_sig = sig
            best_true = tr
            best_sig_possible = len(kt) >= thr + 3
    if thr < 1 or best is None:
        return None
    if best_true < math.ceil(0.6 * thr):
        return None
    if best_sig_possible and thr > 1 and best_sig < 1:
        return None
    return best


# ---- the offline keytable (M6-KEYTAB) ----


def offline_parse(wire: bytes, seeds, ierg: int | None, x: int, sig_gate: bool):
    """Derive the offline keytable, reparse, VALIDATE (M6-KEYTAB §1.1):
    >= 95% finals in the opcode range, last node RETURN/VERIFY_NEVER_TYPE;
    eval v>5 additionally sig-gates (the encoder garbles wD0 raw bytes).
    Returns (reparse, 'offline-ktab') or None."""
    if seeds is None or ierg is None:
        return None
    thr = u32(wire, 0x30)
    if not (1 <= thr <= 100000):
        return None
    from ..crypto.keytable import kt_generate

    kt = kt_generate(seeds[0], seeds[1], ierg, thr)
    try:
        r = parse_wire(wire, kt, None, x)
    except Exception:
        return None
    if r["thr"] != thr:
        return None
    in_range = sum(1 for n in r["nodes"] if n["final"] is not None and n["final"] <= 206)
    if in_range < 0.95 * thr:
        return None
    if not r["nodes"]:
        return None
    lastf = r["nodes"][-1]["final"]
    if lastf not in (62, 199):
        return None
    if sig_gate:
        sig = sum(1 for n in r["nodes"] if n["sigok"])
        if sig < 1:
            return None
        for n in r["nodes"]:
            if n["final"] is not None and n["sigok"] is False:
                n["final"] = None  # trust final only where the sig validates
    return (r, "offline-ktab")


__all__ = ["best_pair", "capture_pairs", "m5_sample_dir", "offline_parse"]
