"""Object/property families: FETCH_OBJ_* property reads and writes,
unset chains, PRE_INC/DEC_OBJ, ISSET_ISEMPTY_PROP_OBJ, FETCH_THIS."""

from __future__ import annotations

from ..model import LiftContext
from ..operand import class_ref, prop_txt, unwrap, zval_name, zval_php
from ..registry import opcode_handler


@opcode_handler(82, 85, 91, 88, 94)  # FETCH_OBJ_* (container->prop)
def _fetch_obj(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, r.obj(r.ex_op1(n)) + "->" + prop_txt(r.ch(r.ex_op2(n))), i)


@opcode_handler(98)  # FETCH_LIST_R: a list() destructure element read
def _fetch_list(ctx: LiftContext, i: int, end: int) -> int:
    # A run of FETCH_LIST_R over one call result, each paired with an
    # ASSIGN to a CV, is the source's
    #   list($a, $b, ...) = call(...);
    # The staged call temp (`$Vn = call(...); $a = $Vn[0]; ...`) is folded
    # back into the list statement.
    n = ctx.nodes[i]
    r = ctx.render
    e1 = n.ent.get("op1")
    if (
        e1 is not None
        and (e1.kind & 4)
        and n.ent.get("op2") is not None
        and n.ent["op2"].kind == 1
    ):
        vslot = ctx.effSlot.get(f"{i}:op1", n.op1 // 16)
        items: list[tuple[int, str]] = []
        fetches: list[int] = []
        assigns: list[int] = []
        k = i
        while k < ctx.thr:
            nk = ctx.nodes[k]
            if ctx.op.get(k) != 98:
                break
            ek1, ek2 = nk.ent.get("op1"), nk.ent.get("op2")
            if (
                ek1 is None
                or not (ek1.kind & 4)
                or ek2 is None
                or ek2.kind != 1
                or ek2.raw >= len(ctx.zvals)
                or ctx.effSlot.get(f"{k}:op1", nk.op1 // 16) != vslot
            ):
                break
            idx = zval_php(ctx.zvals[ek2.raw], ek2.raw)
            if not idx.lstrip("+-").isdigit() or int(idx) < 0:
                break
            a = k + 1
            if a >= ctx.thr or ctx.op.get(a) != 22:
                break
            an = ctx.nodes[a]
            a1, a2 = an.ent.get("op1"), an.ent.get("op2")
            if (
                a1 is None
                or a1.kind != 8
                or a2 is None
                or not (a2.kind & 4)
                or ctx.effSlot.get(f"{a}:op2", an.op2 // 16) != nk.res // 16
            ):
                break
            items.append((int(idx), ctx.cv_name(a1.raw)))
            fetches.append(k)
            assigns.append(a)
            k = a + 1
        if len(items) >= 2:
            uses = set(ctx.tempUses.get(vslot, []))
            expr = ctx.tempExpr.get(vslot)
            kind = e1.kind
            staged = (
                ctx.temp_name(vslot, kind) + " = " + unwrap(expr) + ";"
                if expr is not None
                else None
            )
            if expr is not None and uses <= set(fetches) and staged is not None:
                hit = None
                for oi in range(len(ctx.out) - 1, max(-1, len(ctx.out) - 6), -1):
                    if ctx.out[oi].strip() == staged:
                        hit = oi
                        break
                if hit is not None:
                    del ctx.out[hit]
                    idxs = {}
                    for ix, nm in items:
                        idxs.setdefault(ix, nm)
                    parts = [idxs.get(x, "") for x in range(max(idxs) + 1)]
                    ctx.line(n)
                    ctx.w(
                        "list("
                        + ", ".join(parts)
                        + ") = "
                        + unwrap(expr)
                        + ";"
                    )
                    for x in fetches + assigns:
                        ctx.bk(x)
                    if k < ctx.thr and ctx.op.get(k) in (70, 127):
                        fe = ctx.nodes[k].ent.get("op1")
                        if (
                            fe is not None
                            and (fe.kind & 6)
                            and ctx.effSlot.get(
                                f"{k}:op1", ctx.nodes[k].op1 // 16
                            )
                            == vslot
                        ):
                            ctx.bk(k)
                            k += 1
                    ctx.emitted += 1
                    return k
    # the element lands through array-deref syntax on the fetched row, not
    # an object property (`$row[0]`, valid on a function-call result)
    return ctx.def_temp(n, r.obj(r.ex_op1(n)) + "[" + r.ch(r.ex_op2(n)) + "]", i)


@opcode_handler(81, 84, 90, 87, 93, 96)  # FETCH_DIM_*
def _fetch_dim(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, r.obj(r.ch(r.ex_op1(n))) + "[" + r.ch(r.ex_op2(n)) + "]", i)


@opcode_handler(157)  # FETCH_CLASS_NAME
def _fetch_class_name(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    e = n.ent.get("op1")
    if e is not None and e.kind == 1 and e.raw < len(ctx.zvals):
        nm = zval_name(ctx.zvals[e.raw])
        if nm is not None:
            return ctx.def_temp(n, class_ref(nm) + "::class", i)
    return ctx.def_temp(n, "get_class(" + r.ch(r.ex_op1(n)) + ")", i)


@opcode_handler(182)  # FETCH_THIS (incl. the ungarbled ISSET_ISEMPTY_THIS)
def _fetch_this(ctx: LiftContext, i: int, end: int) -> int:
    # a kind-2 op1 pointing at a closure temp with a function-() expression
    # is a ktab-garbled BIND_LEXICAL — the DECLARE_LAMBDA look-ahead owns it
    n = ctx.nodes[i]
    e1 = n.ent.get("op1")
    if (
        e1
        and (e1.kind & 6)
        and 0 <= n.op1 // 16 < len(ctx.tempExpr)
        and str(ctx.tempExpr.get(n.op1 // 16, "")).startswith("function (")
    ):
        ctx.bk(i)
        return i + 1
    return ctx.def_temp(n, "$this", i)


@opcode_handler(97)  # FETCH_OBJ_UNSET
def _fetch_obj_unset(ctx: LiftContext, i: int, end: int) -> int:
    # a fetch staged for unset(): res temp feeds the UNSET_OBJ chain
    n = ctx.nodes[i]
    r = ctx.render
    return ctx.def_temp(n, r.obj(r.ex_op1(n)) + "->" + prop_txt(r.ch(r.ex_op2(n))), i)


@opcode_handler(76)  # UNSET_OBJ: unset($obj->prop)
def _unset_obj(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    # the op1 temp is the FETCH_OBJ_UNSET-resolved receiver chain
    ctx.line(n)
    ctx.w(
        "unset(" + r.obj(r.ex(n, "op1")) + "->" + prop_txt(r.ch(r.ex(n, "op2"))) + ");"
    )
    ctx.emitted += 1
    return i + 1


@opcode_handler(132, 133)  # PRE_INC_OBJ / PRE_DEC_OBJ
def _pre_incdec_obj(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    sym = "++" if ctx.op[i] == 132 else "--"
    if n.ent.get("op2"):
        e = r.obj(r.ex_op1(n)) + "->" + prop_txt(r.ch(r.ex_op2(n)))
    else:
        e = r.ch(r.ex_op1(n))
    return ctx.def_temp(n, sym + e, i)


@opcode_handler(148)  # ISSET_ISEMPTY_PROP_OBJ (ext&2 = empty)
def _isset_prop(ctx: LiftContext, i: int, end: int) -> int:
    n = ctx.nodes[i]
    r = ctx.render
    fn = "empty" if (n.ext & 3) else "isset"
    arg = r.obj(r.ex_op1(n)) + "->" + prop_txt(r.ch(r.ex_op2(n)))  # bare prop
    return ctx.def_temp(n, fn + "(" + arg + ")", i)
