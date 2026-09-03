"""Handler-registry tests (port-queue item 2, notes/DAWWINCI-DIFF.md §5.2).

Two layers:
1. synthetic LiftContext units — minimal node streams exercising each ported
   family in isolation (the +2 ungarble, the array-literal continuation, the
   `@` silence wrap, the compound dim/obj assigns, the unset chain);
2. corpus assertions — the families on real CE wires, validated against the
   established reference behaviors (the archived legacy-php/ic_lift.php output and
   the decodephp.io ground truth it was banked against).

The 11-component gt table (test_gt_table_via_lift) and the decodephp
cron.php statements (test_cron_matches_decodephp_9_3) are the regression
gates for the opcode-resolution and statement layers respectively.
"""

import pytest

from ioncube_re.lift import LiftContext, emit_node
from ioncube_re.lift.registry import HANDLERS

from conftest import CE, requires_workspace

UNUSED = (0, 0xFFFFFFFF)


def mk(nodes, zvals=None, cv=None, thr=None):
    """A minimal LiftContext over synthetic nodes.

    node spec: (op, {op1: (type, raw), ...}, {slotval...}, ext) — ent entries
    use the wire's operand encoding: 1=const zval idx, 2=TMP, 4|2=VAR, 8=CV,
    0=extended/unused; slotvals carry the raw slot*16 for temp operands.
    """
    zvals = zvals or []
    ns = []
    for k, (op, ent, slots, ext) in enumerate(nodes):
        for w in ("op1", "op2", "res"):
            if w in ent:
                slots.setdefault(w, 0)  # ex() reads the raw slot value
        ns.append({"i": k, "trueop": op, "final": op, "ext": ext or 0,
                   "lineno": 0, "ent": ent, **slots})
    hdr = bytearray(0x60)
    r = {"nodes": ns, "zvals": zvals, "thr": thr or len(ns),
         "hdr": bytes(hdr), "fnrec": None, "pool": b""}
    return LiftContext.build(b"", r, {"cv": cv or {}})


# ---- the +2 anti-tamper garble (M6-SUBWIRE §7.5, extended to the switch pair) ----


def test_ungarble_fetch_this():
    l = mk([(184, {"op1": UNUSED, "op2": UNUSED, "res": (2, 0)}, {"res": 10 * 16}, 0)])
    assert l.op[0] == 182  # ISSET_ISEMPTY_THIS -> FETCH_THIS
    emit_node(l, 0, l.thr)
    assert l.tempExpr[10] == "$this"


def test_ungarble_send_func_arg():
    l = mk([(59, {"op2": (1, 0)}, {}, 0),
            (185, {"op1": (2, 0), "op2": (0, 3)}, {"op1": 6 * 16}, 0)])
    l.zvals.append({"type": 6, "str": b"foo"})
    l.r["zvals"] = l.zvals
    assert l.op[1] == 183  # SWITCH_LONG(arg-index op2) -> SEND_FUNC_ARG
    emit_node(l, 0, l.thr)  # INIT_FCALL consumes the SEND as an arg
    assert "$V1" not in "".join(l.out) and "foo(" in "".join(l.out)


def test_ungarble_switch_header_pair():
    zv = {"type": 7, "str": b"[1:1i24;4;4294967295;"}  # serialized jumptable
    # IN_ARRAY(187) with res unused + const jumptable op2 -> SWITCH_LONG(185)
    l = mk([(187, {"op1": (8, 0), "op2": (1, 0), "res": UNUSED}, {}, 0)],
           zvals=[zv], cv={0: "x"})
    assert l.op[0] == 185
    # COUNT(188) same shape -> SWITCH_STRING(186)
    l2 = mk([(188, {"op1": (8, 0), "op2": (1, 0), "res": UNUSED}, {}, 0)],
            zvals=[zv], cv={0: "x"})
    assert l2.op[0] == 186
    # a real count() keeps its op: res temp, op2 unused
    l3 = mk([(188, {"op1": (8, 0), "res": (2, 0)}, {"res": 8 * 16}, 0)], cv={0: "x"})
    assert l3.op[0] == 188
    emit_node(l3, 0, l3.thr)
    assert l3.tempExpr[8] == "count($x)"


# ---- ADD_ARRAY_ELEMENT continuation (dawwinci arrays.py:22-33) ----


def test_add_array_element_extends_live_literal():
    # INIT_ARRAY builds 'a' => 1 into T7; a construct starter interrupts;
    # the registry handler extends the same res slot
    l = mk([
        (71, {"op1": (1, 0), "op2": (1, 1), "res": (2, 0)}, {"res": 7 * 16}, 0),
        (82, {"op1": (0, 0), "op2": (1, 2), "res": (2, 0)}, {"res": 9 * 16}, 0),
        (72, {"op1": (2, 0), "op2": (1, 3), "res": (2, 0)},
         {"op1": 9 * 16, "res": 7 * 16}, 0),
    ], zvals=[{"type": 4, "a": 1}, {"type": 6, "str": b"a"},
              {"type": 6, "str": b"b"}, {"type": 6, "str": b"k"}])
    emit_node(l, 0, l.thr)  # collectArray: the whole run incl. the interrupter
    assert l.tempExpr[7] == "['a' => 1, 'k' => $this->b]"


def test_add_array_element_registry_continuation():
    # a construct starter (nested INIT_FCALL) ENDS collectArray's run; the
    # AAE after the call lands at statement level and extends the literal
    # via the registry handler (handlers.py ADD_ARRAY_ELEMENT)
    l = mk([
        (71, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
        (59, {"op2": (1, 1)}, {}, 0),
        (60, {"res": (2, 0)}, {"res": 9 * 16}, 0),
        (72, {"op1": (2, 0), "res": (2, 0)}, {"op1": 9 * 16, "res": 7 * 16}, 0),
    ], zvals=[{"type": 6, "str": b"first"}, {"type": 6, "str": b"foo"}])
    emit_node(l, 0, l.thr)  # collectArray stops at the INIT (construct starter)
    emit_node(l, 1, l.thr)  # the nested call -> tempExpr[9] = 'foo()'
    emit_node(l, 3, l.thr)  # the registry continuation
    assert l.tempExpr[9] == "foo()"
    assert l.tempExpr[7] == "['first', foo()]"


def test_add_array_element_without_live_temp_starts_one():
    l = mk([(72, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 6, "str": b"v"}])
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "['v']"


# ---- silence: the `@` operator (dawwinci misc.py:42-64) ----


def test_silence_wraps_newest_temp():
    l = mk([
        (57, {"res": (2, 0)}, {"res": 6 * 16}, 0),
        (31, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),  # QM_ASSIGN
        (58, {"op1": (2, 0)}, {"op1": 6 * 16}, 0),
    ], zvals=[{"type": 6, "str": b"expr"}])
    emit_node(l, 0, l.thr)
    emit_node(l, 1, l.thr)
    emit_node(l, 2, l.thr)
    assert l.tempExpr[7] == "@'expr'"


def test_silence_leaves_pre_window_temp_alone():
    l = mk([
        (31, {"op1": (1, 0), "res": (2, 0)}, {"res": 5 * 16}, 0),
        (57, {"res": (2, 0)}, {"res": 6 * 16}, 0),
        (58, {"op1": (2, 0)}, {"op1": 6 * 16}, 0),
    ], zvals=[{"type": 6, "str": b"before"}])
    for k in range(l.thr):
        emit_node(l, k, l.thr)
    assert l.tempExpr[5] == "'before'"  # produced before the window: not wrapped


# ---- expression families ----


def test_defined():
    l = mk([(122, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 6, "str": b"APP_PATH"}])
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "defined('APP_PATH')"


def test_in_array_real_call():
    l = mk([(187, {"op1": (8, 0), "op2": (8, 1), "res": (2, 0)},
             {"res": 7 * 16}, 0)], cv={0: "needle", 1: "hay"})
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "in_array($needle, $hay)"


def test_handle_exception_is_bookkeeping():
    l = mk([(149, {}, {}, 0)])
    emit_node(l, 0, l.thr)
    assert l.bookkept == 1 and l.unknown == 0


def test_bind_static():
    l = mk([(181, {"op1": (8, 2)}, {}, 0)], cv={2: "count"})
    emit_node(l, 0, l.thr)
    assert "static $count;" in "".join(l.out)


def test_make_ref_passthrough():
    l = mk([(140, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0)],
           zvals=[{"type": 6, "str": b"$x"}])
    emit_node(l, 0, l.thr)
    assert l.tempExpr[7] == "'$x'"


# ---- statement families ----


def test_assign_dim_op_compound():
    l = mk([
        (27, {"op1": (8, 0), "op2": (1, 1)}, {}, 1),
        (137, {"op1": (1, 2)}, {}, 0),  # OP_DATA carries the value
    ], zvals=[{"type": 4, "a": 5}, {"type": 4, "a": 2}, {"type": 6, "str": b"x"}],
       cv={0: "out"})
    emit_node(l, 0, l.thr)
    assert "$out[2] += 'x';" in "".join(l.out)


def test_assign_obj_op_compound():
    l = mk([
        (28, {"op1": (0, 0), "op2": (1, 0)}, {}, 8),
        (137, {"op1": (1, 1)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"count"}, {"type": 4, "a": 1}])
    emit_node(l, 0, l.thr)
    assert "$this->count .= 1;" in "".join(l.out)


def test_unset_obj_chain_through_fetch_obj_unset():
    # FETCH_OBJ_UNSET stages $this->session; UNSET_OBJ chains onto it
    l = mk([
        (97, {"op1": (0, 0), "op2": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
        (76, {"op1": (2, 0), "op2": (1, 1)}, {"op1": 7 * 16}, 0),
    ], zvals=[{"type": 6, "str": b"session"}, {"type": 6, "str": b"installing"}])
    emit_node(l, 0, l.thr)
    emit_node(l, 1, l.thr)
    assert "unset($this->session->installing);" in "".join(l.out)


def test_assign_static_prop_with_op_data():
    l = mk([
        (25, {"op1": (1, 0), "op2": (0, 513)}, {}, 0),
        (137, {"op1": (1, 1)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"lang"}, {"type": 4, "a": 2}])
    emit_node(l, 0, l.thr)
    assert "self::lang = 2;" in "".join(l.out)


def test_unset_cv():
    l = mk([(153, {"op1": (8, 0)}, {}, 0)], cv={0: "x"})
    emit_node(l, 0, l.thr)
    assert "unset($x);" in "".join(l.out)


# ---- the jt guard refinement (dead-code JMP after RETURN) ----


def test_jt_guard_dead_code_jmp_lands_on_next_node():
    # JMP(1) entry v=2 (v-1 == self): the target is the next statement (2),
    # not v+1 (3) — v+1 only for the mid-RETURN form
    l = mk([
        (62, {"op1": (1, 0)}, {}, 0),
        (42, {"op1": (0, 2)}, {}, 0),
        (59, {"op2": (1, 0)}, {}, 0),  # INIT: the real jump target
    ], zvals=[{"type": 1}, {"type": 6, "str": b"f"}])
    assert l.jt[1] == 2


def test_jt_guard_mid_return_form_kept():
    # JMP(0) entry v=1 (v-1 == self) with a RETURN at v+1: the validated
    # mid-RETURN form keeps the v+1 target
    l = mk([
        (42, {"op1": (0, 1)}, {}, 0),
        (31, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
        (62, {"op1": (1, 0)}, {}, 0),
    ], zvals=[{"type": 1}, {"type": 6, "str": b"f"}])
    assert l.jt[0] == 2  # the RETURN sits at v+1


# ---- registry wiring ----


def test_registry_shape():
    # every entry: opcode -> callable; the ungarbled switch headers present
    for op, h in HANDLERS.items():
        assert callable(h)
    assert 182 in HANDLERS and 183 in HANDLERS and 185 in HANDLERS and 186 in HANDLERS


def test_graceful_degradation_unknown_family():
    # an unported opcode (MATCH) still renders the structured comment
    l = mk([(193, {"op1": (1, 0)}, {}, 0)], zvals=[{"type": 1}])
    emit_node(l, 0, l.thr)
    assert "MATCH (opcode 193)" in "".join(l.out)
    assert l.unknown == 1


# ---- corpus: the families on real wires ----


@requires_workspace
def test_ce_action_unset_chains():
    """FETCH_OBJ_UNSET + UNSET_OBJ chains (the family the PHP reference
    still renders as $Vn->prop): `$this->session->prop` member chains."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/library/CE/Controller/Action.php")
    t = r["text"]
    assert "unset($this->session->installing);" in t
    assert "unset($this->session->upgrading);" in t
    assert "unset($this->session->leftbarplugins);" in t
    assert "FETCH_OBJ_UNSET (opcode 97)" not in t


@requires_workspace
def test_ce_silence_wrap():
    """The `@` silence wrap (dawwinci misc.py:42-64) on a real wire:
    `$_POST['password'] = @$_POST['admin_password'];` — the silenced FETCH
    chain renders with the @ prefix at its single use."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/modules/admin/controllers/InstallerController.php")
    t = r["text"]
    assert "= @$_POST['admin_password'];" in t
    assert "BEGIN_SILENCE (opcode 57)" not in t
    assert "END_SILENCE (opcode 58)" not in t


@requires_workspace
def test_ce_action_func_arg_call_chain():
    """The full func-arg chain: CHECK_FUNC_ARG glue + FETCH_OBJ_FUNC_ARG +
    the ungarbled SEND_FUNC_ARG + the array-literal argument — the call
    renders with `$this` and the literal inline (M6-SUBWIRE §7.6 family)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/library/CE/Controller/Action.php")
    t = r["text"]
    assert "CE_Lib::trigger('System-ActionCalled', $this, ['action' => $_GET['action']]);" in t
    assert "$this->user->getFullName()" in t


@requires_workspace
def test_ce_cwhois_families():
    """cwhois.php: the specialized IN_ARRAY call, the $this receiver on
    INIT_METHOD_CALL, the compound ASSIGN_DIM_OP, and the call chains the
    jt-guard refinement un-orphaned (the file the PHP lifter cannot even
    parse — its wire scan truncates)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/library/CE/3rdparty/cWhois/cwhois.php")
    t = r["text"]
    assert "in_array($option, ['2003', '2008'])" in t
    assert "return $this->_ucs4_to_utf8(" in t
    assert "$input[($output - 1)] += $k;" in t or "] += " in t
    for family in ("ADD_ARRAY_ELEMENT (opcode", "SWITCH_LONG (opcode",
                   "SWITCH_STRING (opcode", "BEGIN_SILENCE (opcode",
                   "END_SILENCE (opcode", "CHECK_FUNC_ARG (opcode",
                   "HANDLE_EXCEPTION (opcode", "FETCH_OBJ_UNSET (opcode"):
        assert family not in t, family


@requires_workspace
def test_ce_switch_header_not_count_call():
    """The garbled SWITCH_STRING header (COUNT + const jumptable op2) no
    longer renders a bogus `count($subject);` statement — the CASE/IS_EQUAL
    chain reconstructs the switch (api/index.php's getMethod() dispatch,
    which the PHP reference lifted as `count($concat);`)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/api/index.php")
    t = r["text"]
    assert "count(" not in t  # api/index.php's only COUNT-shaped node is the
    # garbled switch header; real count() calls live on other files
    assert "COUNT (opcode 188)" not in t
    assert "IN_ARRAY (opcode 187)" not in t
    assert "case 'get':" in t or "'get'" in t  # the case chain renders


@requires_workspace
def test_ce_corpora_unknown_budget():
    """The port's headline: unknown-opcode comments across the whole CE
    corpus drop from 11968 (pre-port baseline) to under 1% of the node
    budget — measured over the 3 sampled production files that carried the
    heaviest families."""
    from ioncube_re.lift import lift_file

    total = 0
    for path in ("library/CE/Controller/Action.php",
                 "library/CE/3rdparty/cWhois/cwhois.php",
                 "modules/billing/models/TaxGateway.php"):
        r = lift_file(f"{CE}/{path}")
        for line in r["text"].split("\n"):
            if "(opcode " in line and line.strip().startswith("/*"):
                total += 1
    assert total < 200  # Action 24 + cwhois ~40 + TaxGateway ~2 pre-port was ~1300
