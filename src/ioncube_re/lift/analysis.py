"""The context-build analysis passes: the wire normalizations that turn a
parse result into the lifter's working state — the opcode map (official
wire numbers translated to the internal table, plus the internal trueop
normalizations), the jump-target calibration, the +4 VAR-read slot shifts,
the temp def/use registration, the try/catch records and the pool string
resolution. Model.py owns the dataclasses; this module derives.

The wire→internal opcode table lives in ``opcodes.WIRE_TO_INTERNAL``; the
internal trueop normalizations live in ``_ungarble`` below.
"""

from __future__ import annotations

from ..container import i32, u32
from ..opcodes import wire_to_internal
from ..wire import WireReader

# jump-target-calibrated opcodes (target = entry_value - 1)
_JT_OPS = frozenset({42, 43, 44, 46, 47, 48, 152, 169, 185, 186, 193, 194, 196})
_SKIPUSE = frozenset(
    {
        0,
        63,
        64,
        101,
        102,
        103,
        104,
        105,
        70,
        109,
        124,
        # FREE / FREE_OP (70/127) are lifetime bookkeeping, not source
        # reads: counting the switch subject's FREE as a use made its temp
        # statement survive while the switch emitter inlined the subject
        # ($T31 = $_REQUEST['command']; switch ($_REQUEST['command'])).
        127,
        # OP_DATA (137) registers its operand as a real use: the value is
        # read only through this node (ASSIGN_OBJ..OP_DATA), so skipping it
        # made call collectors think the result was unused and emit both a
        # temp statement and the inlined assignment.
        # BIND_LEXICAL + the ktab-garbled 182 variant: the
        # DECLARE_LAMBDA look-ahead consumes them, not a read
        180,
        182,
    }
)
# producers whose result a following VAR read may name with a rotated slot:
# the DO/UCALL forms, NEW, rope, and INCLUDE_OR_EVAL (eval() is a call)
_CALLDEF = frozenset({60, 68, 98, 129, 130, 131, 29, 30, 73})
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
    _for_inits(ctx)


def _for_inits(ctx) -> None:
    """Mark the `for` init nodes: ASSIGN CV=const + entry JMP + bottom-tested
    loop carrying the same CV as the increment directly before the cond."""
    for n in ctx.nodes:
        i = n.i
        e1, e2 = n.ent.get("op1"), n.ent.get("op2")
        if (
            ctx.op.get(i) != 22
            or ctx.op.get(i + 1) != 42
            or e1 is None
            or e1.kind != 8
            or e2 is None
            or e2.kind != 1
            or i + 1 not in ctx.jt
        ):
            continue
        t = ctx.jt[i + 1]
        b = i + 2
        if t <= b:
            continue
        inc = ctx.nodes[t - 1] if t > 0 else None
        if ctx.op.get(t - 1) != 34 or inc is None:
            continue
        ie = inc.ent.get("op1")
        if ie is None or ie.kind != 8 or ie.raw != e1.raw:
            continue
        cond = ctx.nodes[t] if t < ctx.thr else None
        if cond is None:
            continue
        ce = cond.ent.get("op1")
        if ce is not None and ce.kind == 8 and ce.raw == e1.raw:
            ctx.forInit.add(i)


def _resolve_opcodes(ctx) -> None:
    for n in ctx.nodes:
        # trueop (arena/wD0) is already in the internal table; a raw wire
        # final is in the official PHP 8.1/8.2 numbering and must be mapped
        if n.trueop is not None:
            f = n.trueop
        else:
            f = wire_to_internal(n.final)
        ctx.op[n.i] = f
        if f is None:
            ctx.masked += 1


def _unused(n: Node, wname: str) -> bool:
    e = n.ent.get(wname)
    # the unused marker: 0xFFFFFFFF on one encoder generation, bare 0
    # on another's chunk-1 wires
    return e is None or (e.kind == 0 and e.raw in (0, 0xFFFFFFFF))


def _ungarble(ctx) -> None:
    """Normalize the internal by-name/switch trueop shapes.

    The wire's official numbering is mapped to the internal table in
    ``_resolve_opcodes`` (``opcodes.WIRE_TO_INTERNAL``), so the four +2 wire
    forms are normally gone by the time this runs.  The same shapes can
    still arrive as an arena/wD0 trueop, and these are the normalizations
    the reference lifter applies: ISSET_ISEMPTY_THIS(184) with a res-only
    ``$this`` form is FETCH_THIS(182); SEND_FUNC_ARG(183) can appear as
    SWITCH_LONG(185) with a small arg index; the switch headers can appear
    as IN_ARRAY(187)/COUNT(188) with a serialized jumptable in op2."""

    for n in ctx.nodes:
        f = ctx.op[n.i]
        if f is None:
            continue
        if f == 184 and _unused(n, "op1") and _unused(n, "op2") and n.ent.get("res"):
            ctx.op[n.i] = 182
        elif (
            f == 185
            and n.ent.get("op2")
            and n.ent["op2"].kind == 0
            and 1 <= n.ent["op2"].raw <= 15
            and n.ent.get("op1")
            and (n.ent["op1"].kind & 6)
        ):
            ctx.op[n.i] = 183
        elif (
            f in (187, 188)
            and n.ent.get("op2")
            and n.ent["op2"].kind == 1
            and _unused(n, "res")
            and n.ent["op2"].raw < len(ctx.zvals)
            and (ctx.zvals[n.ent["op2"].raw]["type"] & 0xFF) == 7
        ):
            ctx.op[n.i] = 185 if f == 187 else 186
        elif (
            f == 112
            and _unused(n, "res")
            and n.ent.get("op1") is not None
            and n.ent["op1"].kind == 8
            and n.ent.get("op2") is not None
            and n.ent["op2"].kind == 1
            and n.ent["op2"].raw < len(ctx.zvals)
        ):
            # BIND_GLOBAL decoded as INIT_METHOD_CALL: op1 is the CV being
            # bound and op2 names the same variable (`global $settings;`);
            # the unused result distinguishes it from a real call frame
            from .operand import zval_name

            nm = zval_name(ctx.zvals[n.ent["op2"].raw])
            if nm is not None and ctx.cv.get(n.ent["op1"].raw) == nm:
                ctx.op[n.i] = 168  # BIND_GLOBAL


def _alias_149(ctx) -> None:
    """HANDLE_EXCEPTION (149) carrying live operands — the ktab nosig
    aliasing (LINT-GATE.md: 149 decoded where INIT_METHOD_CALL / SEND /
    FETCH_OBJ_W / FETCH_CONSTANT belong, "live operands flow through the
    node"; a genuine 149 landing pad has no operand payload). The shapes
    below are the ones whose successor contract makes the true op
    unambiguous; the remaining value-op aliases (IS_EQUAL, read-side
    FETCH_OBJ_R, ...) stay 149 and degrade like the reference lifter."""
    import re

    from .model import _PLUMBING, _PURE
    from .operand import zval_name

    defs: dict[int, int] = {}
    for m in ctx.nodes:
        e = m.ent.get("res")
        if e and (e.kind & 6):
            defs[m.res >> 4] = m.i
    # slots whose lifetime end is implicit cleanup, never a source value:
    # a foreach's iterator and a switch's subject temp are FREEd on every
    # exit path (a 149 carrying one of them is a FREE, not a `return`).
    freeSlots: set[int] = set()
    silenceSlots: set[int] = set()
    for m in ctx.nodes:
        o = ctx.op.get(m.i)
        if o in (77, 125):
            e = m.ent.get("res")
            if e and (e.kind & 6):
                freeSlots.add(m.res >> 4)
        elif o in (185, 186):
            e = m.ent.get("op1")
            if e and (e.kind & 6):
                freeSlots.add(m.op1 >> 4)
        elif o == 57:  # BEGIN_SILENCE: the marker temp it hands END_SILENCE
            e = m.ent.get("res")
            if e and (e.kind & 6):
                silenceSlots.add(m.res >> 4)
    # FE_FETCH aliases first: the FETCH 149 sits directly after the
    # FE_RESET 149 and reads its iterator temp.  The forward walk cannot
    # retroactively fix the FE_RESET, so resolve the pair together
    # (`foreach ($v as $param => $val)` nested loops: both nodes garbled).
    for n in ctx.nodes:
        if ctx.op[n.i] != 149 or n.i == 0:
            continue
        p = ctx.nodes[n.i - 1]
        pop = ctx.op[p.i]
        if pop not in (77, 125, 149):
            continue
        f1, f2, fr = n.ent.get("op1"), n.ent.get("op2"), n.ent.get("res")
        if not (
            f1 is not None
            and (f1.kind & 6)
            and f2 is not None
            and (f2.kind == 8 or (f2.kind & 6))
            # the key temp may be unused (`foreach ($xs as $v)`)
            and (fr is None or _unused(n, "res") or (fr.kind & 6))
            and (p.res >> 4) == (n.op1 >> 4)
        ):
            continue
        if pop == 149:
            p1, p2, pr = p.ent.get("op1"), p.ent.get("op2"), p.ent.get("res")
            if not (
                p1 is not None
                and (p1.kind & 6)
                and p2 is not None
                and p2.kind == 0
                and 0 < p2.raw <= ctx.thr
                and pr is not None
                and (pr.kind & 6)
            ):
                continue
            ctx.op[p.i] = 77  # FE_RESET_R
        ctx.op[n.i] = 126 if ctx.op[p.i] == 125 else 78  # FE_FETCH_RW/R

    def _do_149(i: int) -> bool:
        """The DO half of a call whose INIT and DO were both garbled: an
        unused-operand 149 with a temporary result right after the head."""
        k = i + 1
        if k >= ctx.thr or ctx.op.get(k) != 149:
            return False
        d = ctx.nodes[k]
        return (
            _unused(d, "op1")
            and _unused(d, "op2")
            and d.ent.get("res") is not None
            and (d.ent["res"].kind & 6)
        )

    def _call_run(i: int) -> bool:
        """A call head's operand prelude + SEND run + DO follows (argument
        expressions may start with arbitrary pure ops, e.g. a concat)."""
        k = i + 1
        while k < ctx.thr and k <= i + 16:
            o = ctx.op.get(k)
            if o in _SEND:
                pass
            elif o in _DO:
                return True
            elif o == 137:
                # the value node of a dim/obj write — a call INIT is never
                # followed by OP_DATA (a garbled ASSIGN_DIM looked like a
                # call head when a later statement's DO was in range)
                return False
            elif o in _PLUMBING or o in _PURE:
                pass
            else:
                return False
            k += 1
        return False

    for n in ctx.nodes:
        if ctx.op[n.i] != 149:
            continue
        e1 = n.ent.get("op1")
        e2 = n.ent.get("op2")
        er = n.ent.get("res")
        nop = ctx.op[n.i + 1] if n.i + 1 < ctx.thr else None

        # RECV_INIT: a 149 in the prologue carrying arg number + default
        # zval + CV result (`function f($a, $b = '')` where the second
        # RECV_INIT is aliased — updateFailover lost $type/$value/$master).
        # The previous node must be a RECV-family node so a genuine
        # handler landing pad is never rewritten.
        if (
            e1 is not None
            and e1.kind == 0
            and 1 <= e1.raw <= 255
            and e2 is not None
            and e2.kind == 1
            and e2.raw < len(ctx.zvals)
            and er is not None
            and er.kind == 8
            and er.raw == e1.raw - 1
            and (
                (n.i == 0 and e1.raw == 1)
                or (n.i > 0 and ctx.op.get(n.i - 1) in (63, 64, 164))
            )
        ):
            ctx.op[n.i] = 64
            continue

        # BIND_GLOBAL: op1 = the CV, op2 = zval naming the same variable
        # (`global $settings;`); no result.  Without this the call-head
        # rule below renders it as `$settings->settings()` and loses the
        # global binding.
        if (
            e1 is not None
            and e1.kind == 8
            and e2 is not None
            and e2.kind == 1
            and e2.raw < len(ctx.zvals)
            and (er is None or er.kind == 0)
        ):
            nm = zval_name(ctx.zvals[e2.raw])
            if nm is not None and ctx.cv.get(e1.raw) == nm:
                ctx.op[n.i] = 168  # BIND_GLOBAL
                continue

        # call head: op2 = callee-name zval, res = the k0 call frame, and
        # the argument run (SEND/DO) follows — the INIT_* the SENDs belong to
        name = None
        if (
            e2 is not None
            and e2.kind == 1
            and e2.raw < len(ctx.zvals)
            and (nop in _SEND + _DO or _call_run(n.i) or _do_149(n.i))
        ):
            name = zval_name(ctx.zvals[e2.raw])
        if (
            name is not None
            and re.match(
                r"^(?:[A-Za-z_][A-Za-z0-9_]*\\)*[A-Za-z_][A-Za-z0-9_]*$", name
            )
            and er is not None
            and er.kind == 0
        ):
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
            if nop == 149 and _do_149(n.i):
                ctx.op[n.i + 1] = 60  # the matching garbled DO_FCALL
            continue

        # FETCH_R: a variable read by name — op1 = the name zval, the
        # unused marker (not an arg-info frame) in op2, res = the temp the
        # following SEND passes (a superglobal call argument garbled to
        # 149: `checkReportName($_REQUEST)`).  Kept ahead of the NEW rule,
        # which otherwise claims the same string operand as a class name.
        nxt = ctx.nodes[n.i + 1] if n.i + 1 < ctx.thr else None
        if (
            e1 is not None
            and e1.kind == 1
            and e1.raw < len(ctx.zvals)
            and e2 is not None
            and e2.kind == 0
            and e2.raw == 0xFFFFFFFF
            and er is not None
            and (er.kind & 6)
            and nop in _SEND
            and nxt is not None
            and nxt.ent.get("op1") is not None
            and (nxt.ent["op1"].kind & 6)
            and (nxt.op1 >> 4) == (n.res >> 4)
        ):
            nm = zval_name(ctx.zvals[e1.raw])
            if nm in (
                "_GET",
                "_POST",
                "_COOKIE",
                "_SERVER",
                "_FILES",
                "_REQUEST",
                "_ENV",
                "_SESSION",
                "GLOBALS",
                "argv",
                "argc",
            ):
                ctx.op[n.i] = 92  # FETCH_R
                continue

        # NEW: op1 = the class-name zval (kind 1), op2 = the k0 arg-info
        # frame, res = the object temp, followed by its SEND run / DO.
        # A real constructor always carries the frame; the unused marker
        # is a by-name variable read, never a class name.
        if (
            e1 is not None
            and e1.kind == 1
            and e1.raw < len(ctx.zvals)
            and e2 is not None
            and e2.kind == 0
            and e2.raw != 0xFFFFFFFF
            and er is not None
            and (er.kind & 6)
            and nop in _SEND + _DO
        ):
            cls = zval_name(ctx.zvals[e1.raw])
            if cls is not None and re.match(
                r"^[A-Za-z_\\][A-Za-z0-9_\\]*$", cls
            ):
                ctx.op[n.i] = 68  # NEW
                continue

        # FE_RESET: op1 = the iterable temp, res = the iterator temp the
        # immediately following FE_FETCH_R/RW reads as its op1, op2 = the
        # loop's exit target (`foreach (.. as $k => $v)`).
        nxt = ctx.nodes[n.i + 1] if n.i + 1 < ctx.thr else None
        ne1 = nxt.ent.get("op1") if nxt is not None else None
        if (
            e1 is not None
            and (e1.kind & 6 or e1.kind == 8)  # CV iterable: foreach ($key ...)
            and er is not None
            and (er.kind & 6)
            and e2 is not None
            and e2.kind == 0
            and 0 < e2.raw <= ctx.thr
            and nop in (78, 126)
            and ne1 is not None
            and (ne1.kind & 6)
            and (nxt.op1 >> 4) == (n.res >> 4)
        ):
            ctx.op[n.i] = 125 if nop == 126 else 77
            continue

        # plain jump: op1 is the 1-based target, with no res/op2 payload.
        # The nosig alias replaces the skipped branch of a ternary.
        if (
            e1 is not None
            and e1.kind == 0
            and 0 < e1.raw <= ctx.thr
            and _unused(n, "op2")
            and _unused(n, "res")
        ):
            ctx.op[n.i] = 42
            continue

        # short-circuit JMPNZ: op1 = the comparison temp, op2 = the branch
        # target, res mirrors op1 (the branch keeps the tested value, so
        # the two operand payloads name the same slot).  The RHS of the
        # `&&` follows; a sibling function in the same class encodes the
        # identical shape as the real JMPNZ (46).
        if (
            e1 is not None
            and (e1.kind & 6)
            and e2 is not None
            and e2.kind == 0
            and 0 < e2.raw <= ctx.thr
            and er is not None
            and (er.kind & 6)
            and (n.res >> 4) == (n.op1 >> 4)
        ):
            ctx.op[n.i] = 46
            continue

        # conditional branch: op1 = condition temp, op2 = the jump target,
        # no result — the garbled JMPZ guarding an if body.  The body
        # follows the branch and the target is the join.
        if (
            e1 is not None
            and (e1.kind & 6)
            and e2 is not None
            and e2.kind == 0
            and 0 < e2.raw <= ctx.thr
            and _unused(n, "res")
        ):
            ctx.op[n.i] = 43
            continue

        # SEND_VAL_EX: op1 = the value, op2 = the k0 arg index 1..15, res
        # mirrors it — a lost call argument (EmailsController n121).
        # A comparison/chain successor means the same operand shape is a
        # garbled dispatch branch (CASE + TEMP + small target), not a SEND.
        if (
            e1 is not None
            and (e1.kind in (1, 8) or (e1.kind & 6))
            and e2 is not None
            and e2.kind == 0
            and 1 <= e2.raw <= 15
            and er is not None
            and er.kind == 0
            and nop not in (16, 17, 18, 42, 43, 44, 46, 47, 48, 194)
        ):
            ctx.op[n.i] = 116
            continue

        # staged write-fetch: op1 = container temp, op2 = string prop/key,
        # res = the temp the NEXT ASSIGN_DIM/ASSIGN_OBJ writes through —
        # FETCH_OBJ_W/FETCH_DIM_W by the op1 def's family
        # (EmailsController n99: $this->view->emailTypes[...] =)
        nxt = ctx.nodes[n.i + 1] if n.i + 1 < ctx.thr else None
        if (
            e1 is not None
            and (e1.kind & 6)
            and e2 is not None
            and e2.kind == 1
            and er is not None
            and (er.kind & 6)
            and nop in (23, 24)
            and nxt is not None
        ):
            ne1 = nxt.ent.get("op1")
            if ne1 is not None and (ne1.kind & 6) and (nxt.op1 >> 4) == (n.res >> 4):
                d = defs.get(n.op1 >> 4)
                ctx.op[n.i] = (
                    85
                    if (d is not None and ctx.op[d] in (82, 85, 88, 91, 94, 98))
                    else 84
                )
                continue

        # FETCH_CONSTANT: op1 unused, op2 = the name string, res = temp
        if (
            e2 is not None
            and e2.kind == 1
            and er is not None
            and (er.kind & 6)
            and (e1 is None or (e1.kind == 0 and e1.raw in (0, 0xFFFFFFFF)))
        ):
            name = zval_name(ctx.zvals[e2.raw]) if e2.raw < len(ctx.zvals) else None
            if name is not None and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                ctx.op[n.i] = 99
            continue

        # FETCH_LIST_R: op1 = the array temp (an explode()/list result),
        # op2 = the integer element index, res = the element temp
        # (`list($a, $b) = explode(...)`; the middle element often garbles)
        if (
            e1 is not None
            and (e1.kind & 6)
            and e2 is not None
            and e2.kind == 1
            and e2.raw < len(ctx.zvals)
            and (ctx.zvals[e2.raw].get("type", 0) & 0xFF) == 4  # IS_LONG
            and er is not None
            and (er.kind & 6)
        ):
            d = defs.get(n.op1 >> 4)
            if d is not None and ctx.op.get(d) in (60, 98, 129, 130, 131):
                ctx.op[n.i] = 98  # FETCH_LIST_R
                continue

        # comparison feeding a dispatch branch: op1 = the subject (CV/temp),
        # op2 = the case key, res = the comparison temp the immediately
        # following JMPNZ tests.  This is one lost label in a CASE chain
        # (some switch chains garble every ~10th label), and the
        # successor contract makes it a comparable value, not a statement.
        if (
            e1 is not None
            and (e1.kind & 6 or e1.kind == 8)
            and e2 is not None
            and e2.kind == 1
            and er is not None
            and (er.kind & 6)
            and nop in (44, 47)
            and nxt is not None
            and nxt.ent.get("op1") is not None
            and (nxt.ent["op1"].kind & 6)
            and (nxt.op1 >> 4) == (n.res >> 4)
        ):
            ctx.op[n.i] = 18  # IS_EQUAL (the switch's loose comparison)
            continue

        # DO_FCALL: no live op1/op2 (res may carry the result), right after
        # the argument run (prev = INIT/NEW/SEND/CHECK_FUNC_ARG) with no DO
        # or SEND following — the result-consuming statement comes next
        # (EmailsController getemailtemplateAction n13: the 0-arg NEW's DO,
        # without which collect_new swallows the whole try body)
        if (
            _unused(n, "op1")
            and _unused(n, "op2")
            and nop is not None
            and nop not in _DO
            # a DO whose result is passed straight to an outer call is
            # followed by a SEND (`_(sprintf(..))`, `foo(bar())`).  Only a
            # temporary result qualifies: a nested call INIT carries its
            # k0 frame in res and is followed by its own SEND run.
            and (nop not in _SEND or (er is not None and (er.kind & 6)))
            and n.i > 0
            and ctx.op[n.i - 1] in (68, 100) + _INIT + _SEND
        ):
            ctx.op[n.i] = 60
            continue

        # value-op ASSIGN aliases: op1 = a CV target, op2 = the value, and
        # NO result temp — a statement-form write. A 149 carrying a res is
        # a value op (the IS_EQUAL/IS_IDENTICAL family with a CV left
        # operand has exactly this shape) and stays 149: rewriting it
        # would fabricate `$x = <const>;` and drop the comparison result.
        # A following OP_DATA means the write is into a dim/obj
        # (ASSIGN_DIM); otherwise it is a scalar ASSIGN. Both were dropped
        # outright while left at 149 (delimCode = dechex(...),
        # $bankDetails['bankcode'] = ...).
        if (
            e1 is not None
            and e1.kind == 8
            and e2 is not None
            and e2.kind in (1, 2, 4, 6, 8)
            and _unused(n, "res")
        ):
            ctx.op[n.i] = 23 if nop == 137 else 22
            continue

        # nested dim/object writes: op1 is a W-fetch temp (the container
        # slot) rather than a CV, op2 the key/name, OP_DATA the value
        # (`$this->gateway_info[$gw][$key] = ...`).  Only the unambiguous
        # forms are rewritten: a DIM-fetch temp with a non-literal key is
        # ASSIGN_DIM, an OBJ-fetch temp with a literal name is ASSIGN_OBJ.
        # A DIM-fetch temp with a literal key is ambiguous (`$a[$i]['x']`
        # vs `$a[$i]->x`) and stays 149.
        if (
            e1 is not None
            and (e1.kind & 6)
            and e2 is not None
            and _unused(n, "res")
            and nop == 137
        ):
            d = defs.get(n.op1 >> 4)
            dop = ctx.op.get(d) if d is not None else None
            if dop == 85 and e2.kind == 1:  # FETCH_OBJ_W + name zval
                ctx.op[n.i] = 24
                continue
            if dop == 84 and e2.kind in (2, 6, 8):  # FETCH_DIM_W + key
                ctx.op[n.i] = 23
                continue

        # ROPE_END: op1 = the rope accumulator temp (defined by the
        # ROPE_INIT/ROPE_ADD run), op2 = the final literal, res = the
        # joined-string temp (`$a . 'x' . $b` whose tail was aliased)
        if (
            e1 is not None
            and (e1.kind & 6)
            and e2 is not None
            and e2.kind == 1
            and er is not None
            and (er.kind & 6)
        ):
            d = defs.get(n.op1 >> 4)
            if d is not None and ctx.op.get(d) in (54, 55):
                ctx.op[n.i] = 56
                continue

        # OP_DATA: the value operand of the preceding write node
        # (ASSIGN_DIM/ASSIGN_OBJ/…_OP) — a 149 with only op1 live.  The
        # write consumes it as its data node, not a statement of its own.
        if (
            e1 is not None
            and (e1.kind & 6 or e1.kind in (1, 8))
            and _unused(n, "op2")
            and _unused(n, "res")
            and n.i > 0
            and ctx.op.get(n.i - 1) in (23, 24, 26, 27, 28)
        ):
            ctx.op[n.i] = 137
            continue

        # END_SILENCE: the closing marker of a BEGIN_SILENCE window (its
        # op1 is the begin node's marker temp), not a returned value.
        if (
            e1 is not None
            and (e1.kind & 6)
            and _unused(n, "op2")
            and _unused(n, "res")
            and (n.op1 >> 4) in silenceSlots
        ):
            ctx.op[n.i] = 58
            continue

        # FREE of a construct-owned temp (a foreach iterator / switch
        # subject): the cleanup on a case/loop exit path, not a return of
        # that internal value.
        if (
            e1 is not None
            and (e1.kind & 6)
            and _unused(n, "op2")
            and _unused(n, "res")
            and (n.op1 >> 4) in freeSlots
        ):
            ctx.op[n.i] = 70
            continue

        # CONCAT of two constant operands — a constant path expression the
        # compiler kept (`include __DIR__ . '/file.php'`); both operands of
        # a comparison would have been constant-folded away.
        if (
            e1 is not None
            and e1.kind == 1
            and e2 is not None
            and e2.kind == 1
            and er is not None
            and (er.kind & 6)
        ):
            ctx.op[n.i] = 53
            continue

        # CONCAT feeding an include directive (a computed include path)
        if (
            e1 is not None
            and e2 is not None
            and er is not None
            and (er.kind & 6)
            and n.i + 1 < ctx.thr
            and ctx.op.get(n.i + 1) == 73
            and (ctx.nodes[n.i + 1].op1 >> 4) == (n.res >> 4)
        ):
            ctx.op[n.i] = 53
            continue

        # FETCH_THIS: a no-operand 149 whose temp the next node uses as an
        # object receiver — `$this->container->...` after a return branch in
        # a closure body (the outer FETCH_THIS is native; inner sites lose
        # it to the alias)
        if (
            _unused(n, "op1")
            and _unused(n, "op2")
            and er is not None
            and (er.kind & 6)
            and nxt is not None
            and ctx.op.get(n.i + 1) in (82, 85, 88, 91, 94, 97)
            and nxt.ent.get("op1") is not None
            and (nxt.ent["op1"].kind & 6)
            and (nxt.op1 >> 4) == (n.res >> 4)
        ):
            ctx.op[n.i] = 182  # FETCH_THIS
            continue

        # DECLARE_LAMBDA_FUNCTION: op1 unused, op2 = the closure ordinal
        # (a small k0 index), res = the closure temp that the immediately
        # following SEND passes to the enclosing call
        nxt = ctx.nodes[n.i + 1] if n.i + 1 < ctx.thr else None
        if (
            (e1 is None or (e1.kind == 0 and e1.raw in (0, 0xFFFFFFFF)))
            and e2 is not None
            and e2.kind == 0
            and 0 <= e2.raw <= 64
            and er is not None
            and (er.kind & 6)
            and nxt is not None
            # the closure temp is consumed by a call argument (SEND) or is
            # an array-literal element (INIT_ARRAY / ADD_ARRAY_ELEMENT
            # op1) — the dependencies.php config array garbles one element
            and ctx.op.get(n.i + 1) in _SEND + (71, 72)
            and nxt.ent.get("op1") is not None
            and (nxt.ent["op1"].kind & 6)
            and (nxt.op1 >> 4) == (n.res >> 4)
        ):
            ctx.op[n.i] = 142  # DECLARE_LAMBDA_FUNCTION
            continue

        # BOOL of an assignment expression: op1 = the result temp of the
        # ASSIGN_OBJ/DIM immediately above (its OP_DATA precedes this
        # node), res = the short-circuit/branch operand.  The right arm of
        # `$a == 'one' && $this->mode = 'two'`.
        if (
            e1 is not None
            and (e1.kind & 6)
            and _unused(n, "op2")
            and er is not None
            and (er.kind & 6)
            and n.i > 0
            and ctx.op.get(n.i - 1) == 137
        ):
            ctx.op[n.i] = 52  # BOOL
            continue


        # value RETURN / ECHO: the 149 carries only the value expression
        # (no result temp, no second operand).  The raw opcode byte
        # distinguishes the two sources this alias stands for: 136 is ECHO,
        # 62 is RETURN.  Both shapes are identical otherwise; treating an
        # echo as a return made every following statement unreachable (the
        # view templates rendered only their first fragment).
        if (
            e1 is not None
            and (e1.kind & 6 or e1.kind in (1, 2, 4, 6, 8))
            and _unused(n, "op2")
            and _unused(n, "res")
        ):
            raw = ctx.r["nodes"][n.i].get("raw", 0) & 0xFF
            ctx.op[n.i] = 136 if raw == 136 else 62


# ---- jump-target calibration ----


def _calibrate_jumps(ctx) -> None:
    for n in ctx.nodes:
        f = ctx.op[n.i]
        if f is None:
            continue
        if f in _JT_OPS and (
            f == 42 and n.ent.get("op1") or f != 42 and n.ent.get("op2")
        ):
            v = (n.ent["op1"] if f == 42 else n.ent["op2"]).raw
            t = v - 1  # entry v = target+1
            if t == n.i or t < 0 or t >= ctx.thr:
                # Relative-target family: the stored value is an offset from
                # this branch (HttpsSetup callback: JMPZ at n2, value 3,
                # target n5 = the function-end RETURN).  Prefer that when it
                # lands on a terminator; otherwise the off-by-one rules.
                rel = n.i + v
                if (
                    0 <= rel < ctx.thr
                    and rel != n.i
                    and ctx.op.get(rel) in (62, 124)
                ):
                    # the branch target can be the consequent's RETURN;
                    # the implicit function-end RETURN is the real join
                    final = ctx.thr - 1
                    if (
                        rel != final
                        and ctx.op.get(final) in (62, 124)
                        and ctx.op.get(rel) == 62
                    ):
                        rel = final
                    t = rel
                else:
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
        if (
            f in (43, 44)
            and n.i in ctx.jt
            and ctx.jt[n.i] < n.i
            and ctx.jt[n.i] not in ctx.dw_edges
        ):
            ctx.dw_edges[ctx.jt[n.i]] = n.i  # do-while back-edge candidates


# ---- the +4 VAR-read normalization ----


def _shift_var_reads(ctx) -> None:
    """Normalize VAR reads of call/NEW results across encoder generations.

    The producer/read VAR slots are rotated differently per call site
    (+2/+3/+4/+5/+6 observed): the assignment after a call or constructor
    reads a slot that is not the producer's result slot.  Normalize the
    read to the producer's slot when the call/NEW is immediately before
    the read on the same source line, plus the fixed +4/+6 generations.
    """
    defs: dict[int, int] = {}
    for n in ctx.nodes:
        e = n.ent.get("res")
        if e and (e.kind & 6):
            defs[n.res // 16] = n.i
    # NEW/DO pairing: a NEW opens a constructor construct that its DO
    # closes, and PHP evaluates the argument run between the two, so the
    # pairs nest like brackets.  A regular INIT_* call opens a call
    # construct closed by its own DO.  The pairing matters because the
    # constructor DO before an ASSIGN may have no result of its own: the
    # object lives in the NEW's slot.  The nearest NEW is the wrong one
    # when the constructor's arguments contain nested `new`s — for
    # `$date = new DateTime('now', new DateTimeZone($tz));` the ASSIGN
    # read is rotated to a slot colliding with the inner NEW, while the
    # assigned object is the outer one.
    doNew: dict[int, int] = {}
    stack: list[tuple[int, int]] = []  # (68/0 marker, node index)
    for n in ctx.nodes:
        o = ctx.op.get(n.i)
        if o == 68:
            stack.append((68, n.i))
        elif o in _INIT:
            stack.append((0, n.i))
        elif o in _DO and stack:
            kind, ni = stack.pop()
            if kind == 68:
                doNew[n.i] = ni
    for n in ctx.nodes:
        for wname in ("op1", "op2"):
            e = n.ent.get(wname)
            if not e or not (e.kind & 4):
                continue  # VAR reads only
            slot = getattr(n, wname) // 16

            def sibling_reads(pslot: int) -> bool:
                # the pending producer is the OTHER operand's call:
                # `strtolower($mac) == strtolower($val['mac'])` must keep
                # the left call's own result slot (both operands share a
                # source line, so the same-line rule would fold them).
                return any(
                    q is not None
                    and (q.kind & 6)
                    and getattr(n, w) // 16 == pslot
                    for w, q in (
                        ("op1", n.ent.get("op1")),
                        ("op2", n.ent.get("op2")),
                    )
                    if w != wname
                )

            def data_reads(pslot: int) -> bool:
                # ASSIGN_DIM/OBJ carry their VALUE in the following
                # OP_DATA node; when that value is the pending call's
                # result, the call is not the producer of this operand
                # (`$retarr[basename($file)] = file($file)` — op2 is the
                # basename key, OP_DATA the file() value).
                if n.i + 1 >= ctx.thr or ctx.op.get(n.i + 1) != 137:
                    return False
                d = ctx.nodes[n.i + 1]
                q = d.ent.get("op1")
                return bool(
                    q is not None
                    and (q.kind & 6)
                    and d.op1 // 16 == pslot
                )

            # A call/NEW result immediately before the read can be encoded
            # with the read at an arbitrary rotated VAR slot (offers: DO res
            # V7, ASSIGN reads V4; VPN: NEW res V6, the ctor DO has no res,
            # ASSIGN reads V1).  Same source line => the read is the
            # producer.
            p = n.i - 1
            if p >= 0 and ctx.op[p] in _DO and _unused(ctx.nodes[p], "res"):
                # the constructor's result temp belongs to its NEW, which
                # sits before the argument run (`new Processor($srv);
                # $p = $V;`); resolve the NEW through the bracket pairing
                found = doNew.get(p)
                p = found if found is not None else p - 1
            if p >= 0 and ctx.op.get(p) in _CALLDEF:
                pn = ctx.nodes[p]
                pe = pn.ent.get("res")
                if pe is not None and (pe.kind & 6):
                    pslot = pn.res // 16
                    if (
                        pslot != slot
                        and not sibling_reads(pslot)
                        and not data_reads(pslot)
                        and getattr(n, "lineno", 0)
                        == getattr(pn, "lineno", -1)
                    ):
                        ctx.effSlot[f"{n.i}:{wname}"] = pslot
                        continue
            if n.i > 0 and ctx.op[n.i - 1] in _DO:
                # this encoder generation writes the call result 6 slots
                # above the VAR slot the immediately following ASSIGN reads
                # (DO res slot 15, ASSIGN op2 slot 9); normalize the read to
                # the producer so the call inlines into the assignment.
                pn = ctx.nodes[n.i - 1]
                pe = pn.ent.get("res")
                if pe is not None and (pe.kind & 6):
                    pslot = pn.res // 16
                    if (
                        pslot == slot + 6
                        and not sibling_reads(pslot)
                        and not data_reads(pslot)
                    ):
                        ctx.effSlot[f"{n.i}:{wname}"] = pslot
                        continue
                    # Another generation writes the value 2 slots above
                    # (one observed closure: DO res V4, foreach-body ASSIGN
                    # reads V2 while V4 is otherwise unused).  The call and the
                    # assignment share the source line.
                    if (
                        pslot == slot + 2
                        and ctx.op[n.i] == 22
                        and not sibling_reads(pslot)
                        and not data_reads(pslot)
                        and getattr(n, "lineno", 0)
                        == getattr(pn, "lineno", -1)
                    ):
                        ctx.effSlot[f"{n.i}:{wname}"] = pslot
                        continue
            # a read immediately after a call (possibly through @-silence /
            # FREE glue) is the call's value even when its slot is stale or
            # rotated far: `$mail_sent = @mail(...)` reads a slot that last
            # held the headers string.  A compiler temp is single-use, so an
            # older non-call def cannot be the intended producer.  An older
            # call/NEW def is still legitimate when it shares the read's
            # source line (two calls as sibling operands), but a call from
            # an earlier line has been overwritten by this one.
            p2 = n.i - 1
            while p2 >= 0 and ctx.op.get(p2) in (57, 58, 70, 127, 0, 100):
                p2 -= 1
            if p2 >= 0 and ctx.op.get(p2) in _DO:
                pn = ctx.nodes[p2]
                pe = pn.ent.get("res")
                if pe is not None and (pe.kind & 6):
                    pslot = pn.res // 16
                    own = defs.get(slot)
                    own_stale = own is None
                    if own is not None and own < p2:
                        op_own = ctx.op.get(own)
                        own_stale = (
                            op_own not in _CALLDEF
                            or getattr(n, "lineno", 0)
                            != getattr(ctx.nodes[own], "lineno", -1)
                        )
                    if (
                        pslot != slot
                        and not sibling_reads(pslot)
                        and not data_reads(pslot)
                        and own_stale
                    ):
                        ctx.effSlot[f"{n.i}:{wname}"] = pslot
                        continue
            if slot in defs and defs[slot] < n.i:
                continue  # own def precedes: real slot
            er = n.ent.get("res")
            if er is not None and (er.kind & 6) and n.res // 16 == slot:
                # an in-place identity op (SEPARATE) reads the slot it
                # writes; its own def makes the -4 fallback mis-map it
                continue
            d4 = defs.get(slot - 4)
            if d4 is not None and d4 < n.i and ctx.op[d4] in _CALLDEF:
                ctx.effSlot[f"{n.i}:{wname}"] = slot - 4


# ---- temp def/use registration ----


def _register_temps(ctx) -> None:
    ctx.tempDefCount: dict[int, int] = {}
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
                ctx.tempDefCount[slot] = ctx.tempDefCount.get(slot, 0) + 1
            elif ctx.op[n.i] not in _SKIPUSE:
                if (
                    ctx.op[n.i] == 156
                    and n.ent.get("res")
                    and (n.ent["res"].kind & 6)
                    and n.res // 16 == slot
                ):
                    # SEPARATE copies in place: the read is the same value
                    # its producer already exposes, not an extra use
                    continue
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
        # A body with no prologue RECV/HANDLE_EXCEPTION nodes starts the try
        # region at node 0, so keep `s == 0` (functions with parameters get a
        # 1-2 node prologue and a nonzero start).
        if 0 <= s < ctx.thr and 0 < h < ctx.thr:
            out.append((s, h))
    return out


def _resolve_pool_strings(ctx) -> None:
    """Pool strings the parser left unset (lowercase flag / empty)."""
    for zi, z in enumerate(ctx.zvals):
        if "off" not in z or "str" in z:
            continue
        off = z["off"]
        if (
            (off & 0x10000000)
            and z.get("len", 0) > 0
            and (off & ~0x10000000) < len(ctx.r["pool"])
        ):
            off0 = off & ~0x10000000
            ctx.zvals[zi]["str"] = ctx.r["pool"][off0 : off0 + z["len"]]
        elif z.get("len", -1) == 0 and (off & 0xFFFFFFFF) < 0x10000000:
            ctx.zvals[zi]["str"] = b""  # the empty-string constant
