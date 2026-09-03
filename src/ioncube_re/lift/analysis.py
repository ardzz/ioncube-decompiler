"""The context-build analysis passes: the wire normalizations that turn a
parse result into the lifter's working state — the opcode map with the +2
anti-tamper ungarble, the jump-target calibration, the +4 VAR-read slot
shifts, the temp def/use registration, the try/catch records and the pool
string resolution. Model.py owns the dataclasses; this module derives.

The +2 anti-tamper garble table lives HERE (M6-SUBWIRE §7.5 + the
SWITCH_LONG/SWITCH_STRING pair extension, HANDLERS-PORT §1) — one place,
citing its derivation.
"""

from __future__ import annotations

from ..container import i32, u32
from ..wire import WireReader

# jump-target-calibrated opcodes (M5C-LIFTER §1.2: target = entry_value - 1)
_JT_OPS = frozenset({42, 43, 44, 46, 47, 48, 152, 169, 185, 186, 193, 194, 196})
_SKIPUSE = frozenset({0, 63, 64, 101, 102, 103, 104, 105, 70, 109, 124, 137})
_CALLDEF = frozenset({60, 68, 129, 130, 131})
_SEND = (65, 116, 117, 66, 67, 106, 50, 165, 119, 120, 183)
_DO = (60, 129, 130, 131)
_INIT = (59, 61, 69, 112, 113, 118, 128)


def analyze(ctx) -> None:
    _resolve_opcodes(ctx)
    _ungarble(ctx)
    _alias_149(ctx)
    _calibrate_jumps(ctx)
    _shift_var_reads(ctx)
    _register_temps(ctx)
    ctx.tryBlocks = _tc_records(ctx)
    _resolve_pool_strings(ctx)


def _resolve_opcodes(ctx) -> None:
    for n in ctx.nodes:
        f = n.trueop if n.trueop is not None else n.final
        ctx.op[n.i] = f
        if f is None:
            ctx.masked += 1

def _unused(n: Node, wname: str) -> bool:
    e = n.ent.get(wname)
    # the unused marker: 0xFFFFFFFF on the CE generation, bare 0
    # on the Blesta generation's chunk-1 wires (license.php load
    # n52: Loader::loadModels($this, ...) arrives as 184/e0/e0)
    return e is None or (e.kind == 0 and e.raw in (0, 0xFFFFFFFF))


def _ungarble(ctx) -> None:
    """The +2 anti-tamper garble (M6-SUBWIRE §7.5 + the switch pair).

    The encoder stores four opcodes +2: FETCH_THIS(182) as
    ISSET_ISEMPTY_THIS(184) [res-only $this form; op1/op2 carry the
    unused marker type0/0xffffffff], SEND_FUNC_ARG(183) as
    SWITCH_LONG(185) [op2 = a small arg index 1..15; a real
    SWITCH_LONG's op2 is a jumptable], SWITCH_LONG(185) as IN_ARRAY(187)
    and SWITCH_STRING(186) as COUNT(188) [both res unused with a const
    serialized jumptable in op2 — a real IN_ARRAY/COUNT always carries
    a res temp]. The first two match ic_lift.php verbatim; the switch
    pair extends the same +2 family (HANDLERS-PORT §1)."""

    for n in ctx.nodes:
        f = ctx.op[n.i]
        if f is None:
            continue
        if f == 184 and _unused(n, "op1") and _unused(n, "op2") and n.ent.get("res"):
            ctx.op[n.i] = 182
        elif f == 185 and n.ent.get("op2") and n.ent["op2"].kind == 0 \
                and 1 <= n.ent["op2"].raw <= 15 and n.ent.get("op1") \
                and (n.ent["op1"].kind & 6):
            ctx.op[n.i] = 183
        elif f in (187, 188) and n.ent.get("op2") and n.ent["op2"].kind == 1 \
                and _unused(n, "res") and n.ent["op2"].raw < len(ctx.zvals) \
                and (ctx.zvals[n.ent["op2"].raw]["type"] & 0xFF) == 7:
            ctx.op[n.i] = 185 if f == 187 else 186


def _alias_149(ctx) -> None:
    """HANDLE_EXCEPTION (149) carrying live operands — the ktab nosig
    aliasing (LINT-GATE.md: 149 decoded where INIT_METHOD_CALL / SEND /
    FETCH_OBJ_W / FETCH_CONSTANT belong, "live operands flow through the
    node"; a genuine 149 landing pad has no operand payload). The four
    shapes below are the ones whose successor contract makes the true op
    unambiguous; the value-op aliases (IS_EQUAL, read-side FETCH_OBJ_R,
    ASSIGN...) stay 149 and degrade like the reference oracle."""
    import re

    from .operand import zval_name

    defs: dict[int, int] = {}
    for m in ctx.nodes:
        e = m.ent.get("res")
        if e and (e.kind & 6):
            defs[m.res >> 4] = m.i
    for n in ctx.nodes:
        if ctx.op[n.i] != 149:
            continue
        e1 = n.ent.get("op1")
        e2 = n.ent.get("op2")
        er = n.ent.get("res")
        nop = ctx.op[n.i + 1] if n.i + 1 < ctx.thr else None

        # call head: op2 = callee-name zval, res = the k0 call frame, and
        # the argument run (SEND/DO) follows — the INIT_* the SENDs belong to
        name = None
        if e2 is not None and e2.kind == 1 and e2.raw < len(ctx.zvals) and nop in _SEND + _DO:
            name = zval_name(ctx.zvals[e2.raw])
        if name is not None and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name) \
                and er is not None and er.kind == 0:
            if e1 is None or (e1.kind == 0 and e1.raw == 0xFFFFFFFF):
                ctx.op[n.i] = 61  # plain function call
            elif e1.kind == 1 or (e1.kind == 0 and e1.raw == 514):
                ctx.op[n.i] = 113  # static: class-name op1 / the 514 parent sentinel
            elif e1.kind == 8 or (e1.kind & 6):
                ctx.op[n.i] = 112  # method call: receiver op1
            elif re.match(r"^[a-z][a-z0-9_]*$", name):
                ctx.op[n.i] = 61  # lowercase name + junk k0 op1: builtin-ish
            else:
                ctx.op[n.i] = 112  # camelCase + junk k0 op1: the $this marker
            continue

        # SEND_VAL_EX: op1 = the value, op2 = the k0 arg index 1..15, res
        # mirrors it — a lost call argument (EmailsController n121)
        if e1 is not None and (e1.kind in (1, 8) or (e1.kind & 6)) \
                and e2 is not None and e2.kind == 0 and 1 <= e2.raw <= 15 \
                and er is not None and er.kind == 0:
            ctx.op[n.i] = 116
            continue

        # staged write-fetch: op1 = container temp, op2 = string prop/key,
        # res = the temp the NEXT ASSIGN_DIM/ASSIGN_OBJ writes through —
        # FETCH_OBJ_W/FETCH_DIM_W by the op1 def's family
        # (EmailsController n99: $this->view->emailTypes[...] =)
        nxt = ctx.nodes[n.i + 1] if n.i + 1 < ctx.thr else None
        if e1 is not None and (e1.kind & 6) and e2 is not None and e2.kind == 1 \
                and er is not None and (er.kind & 6) and nop in (23, 24) and nxt is not None:
            ne1 = nxt.ent.get("op1")
            if ne1 is not None and (ne1.kind & 6) and (nxt.op1 >> 4) == (n.res >> 4):
                d = defs.get(n.op1 >> 4)
                ctx.op[n.i] = 85 if (d is not None and ctx.op[d] in (82, 85, 88, 91, 94, 98)) else 84
                continue

        # FETCH_CONSTANT: op1 unused, op2 = the name string, res = temp
        if e2 is not None and e2.kind == 1 and er is not None and (er.kind & 6) \
                and (e1 is None or (e1.kind == 0 and e1.raw in (0, 0xFFFFFFFF))):
            name = zval_name(ctx.zvals[e2.raw]) if e2.raw < len(ctx.zvals) else None
            if name is not None and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                ctx.op[n.i] = 99
            continue

        # DO_FCALL: no live op1/op2 (res may carry the result), right after
        # the argument run (prev = INIT/NEW/SEND/CHECK_FUNC_ARG) with no DO
        # or SEND following — the result-consuming statement comes next
        # (EmailsController getemailtemplateAction n13: the 0-arg NEW's DO,
        # without which collect_new swallows the whole try body)
        if _unused(n, "op1") and _unused(n, "op2") and nop is not None \
                and nop not in _DO and nop not in _SEND and n.i > 0 \
                and ctx.op[n.i - 1] in (68, 100) + _INIT + _SEND:
            ctx.op[n.i] = 60

# ---- jump-target calibration (M5C-LIFTER §1.2) ----

def _calibrate_jumps(ctx) -> None:
    for n in ctx.nodes:
        f = ctx.op[n.i]
        if f is None:
            continue
        if f in _JT_OPS and (f == 42 and n.ent.get("op1") or f != 42 and n.ent.get("op2")):
            v = (n.ent["op1"] if f == 42 else n.ent["op2"]).raw
            t = v - 1  # entry v = target+1 (M6 §1.3)
            if t == n.i or t < 0 or t >= ctx.thr:
                # the off-by-one family: a dead-code JMP after RETURN
                # targets the next node (v); the mid-RETURN form targets
                # the RETURN itself (v+1). Taking v+1 unconditionally
                # skipped the next statement's INIT and orphaned the
                # call chain (cwhois.php n135: JMP e136 -> INIT 136).
                t = v + 1 if ctx.op.get(v + 1) in (62, 124) else v
            if 0 <= t < ctx.thr:
                ctx.jt[n.i] = t
        if f in (77, 125) and n.ent.get("op2"):  # FE_RESET_R/RW: exit = v
            ctx.feExit[n.i] = min(n.ent["op2"].raw, ctx.thr - 1)
        if f in (43, 44) and n.i in ctx.jt and ctx.jt[n.i] < n.i \
                and ctx.jt[n.i] not in ctx.dw_edges:
            ctx.dw_edges[ctx.jt[n.i]] = n.i  # do-while back-edge candidates

# ---- the +4 VAR-read normalization (M6-SUBWIRE §7.4) ----

def _shift_var_reads(ctx) -> None:
    """The Blesta generation encodes a VAR read of a call/NEW result 4
    slots above the producer's res slot (V26 = DO_FCALL res; ASSIGN op2
    = V30): the read's own slot has no def at/before the node, slot-4
    is defined by a DO_FCALL/NEW before it. Normalize those reads to
    slot-4 so the temp def/use analysis and the expression inlining
    line up (the eval corpus never hit the pattern)."""
    defs: dict[int, int] = {}
    for n in ctx.nodes:
        e = n.ent.get("res")
        if e and (e.kind & 6):
            defs[n.res // 16] = n.i
    for n in ctx.nodes:
        for wname in ("op1", "op2"):
            e = n.ent.get(wname)
            if not e or not (e.kind & 4):
                continue  # VAR reads only
            slot = getattr(n, wname) // 16
            if slot in defs and defs[slot] < n.i:
                continue  # own def precedes: real slot
            d4 = defs.get(slot - 4)
            if d4 is not None and d4 < n.i and ctx.op[d4] in _CALLDEF:
                ctx.effSlot[f"{n.i}:{wname}"] = slot - 4

# ---- temp def/use registration ----

def _register_temps(ctx) -> None:
    for n in ctx.nodes:
        for wname in ("res", "op1", "op2"):
            e = n.ent.get(wname)
            if not e or not (e.kind & 6):
                continue
            slot = getattr(n, wname) // 16
            if wname != "res":
                es = ctx.effSlot.get(f"{n.i}:{wname}")
                if es is not None:
                    slot = es
            if wname == "res":
                ctx.tempDef[slot] = n.i
            elif ctx.op[n.i] not in _SKIPUSE:
                ctx.tempUses.setdefault(slot, []).append(n.i)

# ---- try/catch records + pool strings ----

def _tc_records(ctx) -> list[tuple[int, int]]:
    from ..container import i32

    tc = u32(ctx.r["hdr"], 0x50)
    if not (1 <= tc <= 1000):
        return []
    rd = WireReader(ctx.wire)
    rd.raw(0x7C)
    rd.raw(4)
    rd.u32()
    if i32(ctx.r["hdr"], 8) != 0:
        rd.raw(16)
    if u32(ctx.r["hdr"], 0x68) != 0:
        rd.raw(16)
    rd.i32()
    b = rd.raw(tc * 16)
    out = []
    for i in range(tc):
        s = u32(b, i * 16)
        h = u32(b, i * 16 + 4)
        if 0 < s < ctx.thr and 0 < h < ctx.thr:
            out.append((s, h))
    return out

def _resolve_pool_strings(ctx) -> None:
    """Pool strings the parser left unset (lowercase flag / empty)."""
    for zi, z in enumerate(ctx.zvals):
        if "off" not in z or "str" in z:
            continue
        off = z["off"]
        if (off & 0x10000000) and z.get("len", 0) > 0 \
                and (off & ~0x10000000) < len(ctx.r["pool"]):
            off0 = off & ~0x10000000
            ctx.zvals[zi]["str"] = ctx.r["pool"][off0:off0 + z["len"]]
        elif z.get("len", -1) == 0 and (off & 0xFFFFFFFF) < 0x10000000:
            ctx.zvals[zi]["str"] = b""  # the empty-string constant


