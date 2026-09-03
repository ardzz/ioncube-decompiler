"""Variable/assignment families: ASSIGN and its compound/property/dim
forms (with the OP_DATA value-inlining), the FETCH var-by-name family
(superglobals / $GLOBALS), FETCH_CONSTANT, ROPE string interpolation,
isset/empty on vars and dims, unset, and the inc/dec statements."""

from __future__ import annotations

import re

from ..model import LiftContext
from ..operand import bare, php_quote, unwrap, zval_name
from ..registry import opcode_handler

_SUPERGLOBALS = ("_GET", "_POST", "_COOKIE", "_SERVER", "_FILES",
                 "_REQUEST", "_ENV", "_SESSION", "GLOBALS", "argv", "argc", "this")
# the value-temp defs whose expression may be inlined into an OP_DATA read
# (the manual inline when a def precedes an ASSIGN_OBJ/DIM) — pure defs
# plus the collector producers (DO_FCALL/DO_ICALL/DO_UCALL/DO_FCALL_BY_NAME,
# NEW, INIT_ARRAY): their tempExpr is a full expression with no statement
_PUREDEF = frozenset(range(80, 99)) | frozenset(range(1, 22)) | frozenset(range(173, 179)) \
    | {31, 51, 52, 53, 99, 121, 123, 138, 169, 170} \
    | {60, 68, 71, 129, 130, 131}


@opcode_handler(22)  # ASSIGN
def _assign(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    ctx.line(n)
    v = r.ch(r.ex_op2(n))
    e = n.ent.get("res")
    if e and (e.kind & 6):
        ctx.tempExpr[n.res // 16] = r.ch(r.ex_op2(n))
    ctx.w(r.ch(r.ex_op1(n)) + " = " + v + ";")
    ctx.emitted += 1
    return i + 1


@opcode_handler(34, 35, 36, 37)  # PRE/POST INC/DEC
def _incdec(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    op = ctx.op[i]
    ctx.line(n)
    v = ctx.render.ex_op1(n)
    ctx.w(("++" if op == 34 else "--" if op == 35 else "") + ctx.render.ch(v)
          + ("++" if op == 36 else "--" if op == 37 else "") + ";")
    ctx.emitted += 1
    return i + 1


@opcode_handler(23, 24, 26, 27, 28)  # ASSIGN_DIM/OBJ, ASSIGN_OP, *_OP
def _assign_op(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    op = ctx.op[i]
    r = ctx.render
    dataN = ctx.nodes[i + 1] if i + 1 < ctx.thr and ctx.op[i + 1] == 137 else None
    val = r.ex(dataN, "op1") if dataN is not None else r.ex_op2(n)
    # the OP_DATA value temp: its read is not registered as a use
    # (_SKIPUSE), so inline it manually when a PURE/collector def precedes
    # this assign (FETCH_OBJ_R -> ASSIGN_OBJ -> OP_DATA T57: $this->x = <expr>;
    # DO_FCALL -> ASSIGN_OBJ -> OP_DATA V37: $this->message = $this->user->lang(...))
    if dataN is not None and val is not None and re.match(r"^\$[TV]\d+$", val):
        de = dataN.ent.get("op1")
        if de and (de.kind & 6):
            slot = ctx.effSlot.get(f"{dataN.i}:op1", dataN.op1 // 16)
            d = ctx.tempDef.get(slot)
            if d is not None and d < i and slot in ctx.tempExpr and ctx.op[d] in _PUREDEF \
                    and not any(u >= i for u in ctx.tempUses.get(slot, [])):
                val = ctx.tempExpr[slot]
    ctx.line(n)
    if op in (24, 28):  # ASSIGN_OBJ / ASSIGN_OBJ_OP
        lhs = r.obj(r.ex_op1(n)) + "->" + bare(r.ch(r.ex_op2(n)))
    elif op in (23, 27):  # ASSIGN_DIM / ASSIGN_DIM_OP
        lhs = r.ch(r.ex_op1(n)) + "[" + r.ch(r.ex_op2(n)) + "]"
    else:  # ASSIGN_OP (compound, scalar lhs)
        lhs = r.ch(r.ex_op1(n))
    if op in (26, 27, 28):  # compound forms: $lhs op= $val (ext = the op)
        m = {1: "+", 2: "-", 3: "*", 4: "/", 5: "%", 8: ".", 9: "|", 10: "&",
             11: "^", 12: "**", 6: "<<", 7: ">>"}
        sym = m.get(n.ext)
        if sym is None:
            ctx.w(f"/* ASSIGN_OP ext={n.ext} op1={r.opnd_text(n, 'op1')} */")
            ctx.unknown += 1
            return i + 1
        ctx.w(lhs + f" {sym}= " + r.ch(val) + ";")
        ctx.emitted += 1
        return i + (2 if dataN is not None else 1)
    ctx.w(lhs + " = " + r.ch(val) + ";")
    ctx.emitted += 1
    if dataN is not None:
        ctx.bk(i + 1)
    e = n.ent.get("res")
    if e and (e.kind & 6):
        ctx.tempExpr[n.res // 16] = r.ch(val)
    return i + (2 if dataN is not None else 1)


@opcode_handler(30)  # ASSIGN_REF
def _assign_ref(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    ctx.line(n)
    src = r.ch(r.ex_op2(n))
    ctx.w(r.ch(r.ex_op1(n)) + " = &" + src + ";")
    ctx.emitted += 1
    e = n.ent.get("res")
    if e and (e.kind & 6):
        ctx.tempExpr[n.res // 16] = src
    return i + 1


@opcode_handler(32)  # ASSIGN_OBJ_REF (+ OP_DATA source)
def _assign_obj_ref(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    dataN = ctx.nodes[i + 1] if i + 1 < ctx.thr and ctx.op[i + 1] == 137 else None
    src = r.ch(r.ex(dataN, "op1")) if dataN is not None else r.ch(r.ex_op2(n))
    lhs = r.obj(r.ex_op1(n)) + "->" + bare(r.ch(r.ex_op2(n)))
    ctx.line(n)
    ctx.w(lhs + " = &" + src + ";")
    ctx.emitted += 1
    if dataN is not None:
        ctx.bk(i + 1)
    return i + (2 if dataN is not None else 1)


@opcode_handler(25)  # ASSIGN_STATIC_PROP (+ OP_DATA value)
def _assign_static_prop(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    dataN = ctx.nodes[i + 1] if i + 1 < ctx.thr and ctx.op[i + 1] == 137 else None
    val = r.ch(r.ex(dataN, "op1")) if dataN is not None else r.ch(r.ex_op2(n))
    prop = r.ch(r.ex_op1(n))
    cls = "self"
    e = n.ent.get("op2")
    if e and e.kind == 0:
        # the class operand sentinel family (514 = parent, cf. the INIT
        # static-call map; 513 observed as the self/default sentinel)
        cls = {514: "parent", 515: "static"}.get(e.raw, "self")
    ctx.line(n)
    ctx.w(cls + "::" + bare(prop) + " = " + val + ";")
    ctx.emitted += 1
    if dataN is not None:
        ctx.bk(i + 1)
    return i + (2 if dataN is not None else 1)


def _name_var_text(ctx: LiftContext, n) -> str | None:
    """op1 as a variable NAME zval -> the fetch text: ``$superglobal`` for
    the auto-globals (interned -8..-12 / pool strings, INTERNED.md §2),
    ``$GLOBALS['name']`` otherwise. None when op1 is not a name zval."""
    e = n.ent.get("op1")
    if e is None or e.kind != 1 or e.raw >= len(ctx.zvals):
        return None
    nm = zval_name(ctx.zvals[e.raw])  # pool string OR interned (gap #1)
    if nm is None:
        return None
    if nm in _SUPERGLOBALS:
        return "$" + nm
    return "$GLOBALS[" + php_quote(nm.encode("latin-1")) + "]"


@opcode_handler(80, 83, 86, 89, 92, 95,
               173, 174, 175, 176, 177, 178)  # FETCH_* var-by-name
def _fetch_by_name(ctx: LiftContext, i: int, end: int) -> int:
    """Fetch a variable by its NAME (op1): FETCH_R/W/RW/IS/FUNC_ARG/UNSET and
    the STATIC_PROP reads. In PHP's zend VM this whole opcode set is the
    by-name form (op1 = a CONSTANT name zval, or the name expression for
    ``$$name``); the container forms are FETCH_DIM_*/FETCH_OBJ_*."""
    n = ctx.nodes[i]
    r = ctx.render
    var = _name_var_text(ctx, n)
    if var is not None:
        return ctx.def_temp(n, var, i)
    # unresolved name: the rendered op1 (quoted constant / placeholder), or
    # the oracle's op2 fallback when op1 is not a zval at all
    e = n.ent.get("op1")
    fallback = r.ch(r.ex_op1(n)) if e is not None and e.kind == 1 else r.ch(r.ex_op2(n))
    return ctx.def_temp(n, "$GLOBALS[" + fallback + "]", i)


@opcode_handler(99)  # FETCH_CONSTANT
def _fetch_constant(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    # the name zval raw string, no php_quote escaping: a constant
    # REFERENCE (\Name\Space\CONST), never a literal (ic_lift parity)
    c = None
    e2 = n.ent.get("op2")
    if e2 is not None and e2.kind == 1 and e2.raw < len(ctx.zvals) \
            and "str" in ctx.zvals[e2.raw]:
        c = ctx.zvals[e2.raw]["str"].decode("latin-1")
    if c is None:
        c = bare(r.ch(r.ex_op2(n)))
    return ctx.def_temp(n, "\\" + c, i)


@opcode_handler(54)  # ROPE_INIT (string interpolation)
def _rope_init(ctx: LiftContext, i: int, end: int) -> int:
    ctx.rope = [ctx.render.ch(ctx.render.ex_op2(ctx.nodes[i]))]
    ctx.bookkept += 1
    return i + 1


@opcode_handler(55)  # ROPE_ADD
def _rope_add(ctx: LiftContext, i: int, end: int) -> int:
    ctx.rope.append(ctx.render.ch(ctx.render.ex_op2(ctx.nodes[i])))
    ctx.bookkept += 1
    return i + 1


@opcode_handler(56)  # ROPE_END
def _rope_end(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    ctx.rope.append(r.ch(r.ex_op2(n)))
    parts = [x for x in ctx.rope if x is not None and x != "null"]
    e = " . ".join(unwrap(p) for p in parts)  # interpolation chain, no outer parens
    ctx.rope = []
    return ctx.def_temp(n, e, i)


@opcode_handler(114, 115, 154)  # ISSET_ISEMPTY_VAR / _DIM_OBJ / _CV
def _isset(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    op = ctx.op[i]
    r = ctx.render
    fn = "empty" if (n.ext & 2) else "isset"
    if op == 115:  # _DIM_OBJ: op1[expr][dim]
        arg = r.ch(r.ex_op1(n)) + "[" + r.ch(r.ex_op2(n)) + "]"
    elif op == 114:  # _VAR: op1 may BE the name (empty($_POST) on a superglobal)
        arg = _name_var_text(ctx, n) or r.ch(r.ex_op1(n))
    else:
        arg = r.ch(r.ex_op1(n))
    return ctx.def_temp(n, fn + "(" + arg + ")", i)


@opcode_handler(74, 75)  # UNSET_VAR / UNSET_DIM
def _unset(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    ctx.line(n)
    args = []
    for wname in ("op1", "op2"):
        v = r.ex(n, wname)
        if v is not None:
            args.append(v)
    ctx.w("unset(" + ", ".join(args) + ");")
    ctx.emitted += 1
    return i + 1


@opcode_handler(153)  # UNSET_CV
def _unset_cv(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    ctx.line(n)
    ctx.w("unset(" + ctx.render.ch(ctx.render.ex_op1(n)) + ");")
    ctx.emitted += 1
    return i + 1


@opcode_handler(168)  # BIND_GLOBAL
def _bind_global(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    ctx.line(n)
    ctx.w("global " + ctx.render.ch(ctx.render.ex_op2(n)) + ";")
    ctx.emitted += 1
    return i + 1
