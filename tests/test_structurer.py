"""Structurer-upgrade tests (port-queue items 3-4, notes/DAWWINCI-DIFF.md
§5.3/§5.4): do-while, break/continue levels, ternary folding, the `?:`
JMP_SET full form, the jumptable-header switch (the Blesta IS_EQUAL+JMPNZ
form), the table-driven fallback, and the while-priming bottom-tested
pattern. Synthetic LiftContext fixtures — the model dataclasses make these
cheap — plus corpus assertions for the patterns that fire on real wires
(TaxGateway/Action/license.php).
"""

import pytest

from ioncube_re.lift import LiftContext, emit_node, emit_region
from ioncube_re.lift import loops

from conftest import CE, WORK, requires_workspace

UNUSED = (0, 0xFFFFFFFF)


def mk(nodes, zvals=None, cv=None, thr=None, valid_php=False):
    """A minimal LiftContext over synthetic nodes.

    node spec: (op, {op1: (type, raw), ...}, {slotval...}, ext) — ent entries
    use the wire's operand encoding: 1=const zval idx, 2=TMP, 4|2=VAR, 8=CV,
    0=extended/unused; slotvals carry the raw slot*16 for temp operands.
    Jump ops carry their entry value in op1 (JMP) / op2 (conditional) raw.
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
    ctx = LiftContext.build(b"", r, {"cv": cv or {}})
    ctx.valid_php = valid_php
    return ctx


def out(ctx):
    return "".join(ctx.out)


# ---- do-while (dawwinci structurer.py:235-242) ----


def test_do_while():
    # 0: body; 1: cond def; 2: JMPNZ -> 0 (back edge, reached by fallthrough)
    l = mk([
        (136, {"op1": (1, 0)}, {}, 0),                    # ECHO 'x'
        (20, {"op1": (8, 0), "op2": (1, 1), "res": (2, 0)},
         {"res": 7 * 16}, 0),                             # $i < 10 -> T7
        (44, {"op1": (2, 0), "op2": (0, 1)}, {"op1": 7 * 16}, 0),  # JMPNZ -> 0
        (62, {"op1": (1, 2)}, {}, 0),                     # RETURN
    ], zvals=[{"type": 6, "str": b"x"}, {"type": 4, "a": 10}, {"type": 1}],
       cv={0: "i"})
    emit_region(l, 0, l.thr)
    assert "do {" in out(l)
    assert "} while ($i < 10);" in out(l)
    assert l.unknown == 0


def test_do_while_jmpz_inverts_condition():
    l = mk([
        (136, {"op1": (1, 0)}, {}, 0),
        (20, {"op1": (8, 0), "op2": (1, 1), "res": (2, 0)}, {"res": 7 * 16}, 0),
        (43, {"op1": (2, 0), "op2": (0, 1)}, {"op1": 7 * 16}, 0),  # JMPZ -> 0
        (62, {"op1": (1, 2)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"x"}, {"type": 4, "a": 10}, {"type": 1}],
       cv={0: "i"})
    emit_region(l, 0, l.thr)
    assert "} while (!($i < 10));" in out(l)


def test_bottom_tested_body_is_not_do_while():
    # [JMP -> cond][body][cond][JMPNZ -> body]: the entry JMP form owns the
    # body — do_while_at must refuse (pretested semantics)
    l = mk([
        (42, {"op1": (0, 3)}, {}, 0),                     # JMP -> 2
        (136, {"op1": (1, 0)}, {}, 0),                    # body: ECHO
        (20, {"op1": (8, 0), "op2": (1, 1), "res": (2, 0)}, {"res": 7 * 16}, 0),
        (44, {"op1": (2, 0), "op2": (0, 1)}, {"op1": 7 * 16}, 0),  # JMPNZ -> 1
        (62, {"op1": (1, 2)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"x"}, {"type": 4, "a": 10}, {"type": 1}],
       cv={0: "i"})
    assert l.jt[0] == 2  # the entry JMP over the body to the condition
    dw = loops.do_while_at(l, 1, l.thr)
    assert dw is None  # node 1 is the bottom-tested body, not a do-while


# ---- while-priming (dawwinci structurer.py:296-345, the spec) ----


def test_bottom_tested_while_priming():
    """while ($row = next_row()) { use_row($row); } — the dawwinci test's
    exact shape: priming read before the loop, re-read at the body end."""
    l = mk([
        (42, {"op1": (0, 5)}, {}, 0),                     # 0: JMP -> 4
        (59, {"op2": (1, 0)}, {}, 0),                     # 1: INIT_FCALL use_row
        (65, {"op1": (8, 0)}, {}, 0),                     # 2: SEND $row
        (60, {}, {}, 0),                                    # 3: DO (no res: statement)
        (59, {"op2": (1, 1)}, {}, 0),                     # 4: INIT_FCALL next_row
        (60, {"res": (4, 0)}, {"res": 8 * 16}, 0),        # 5: DO -> V8
        (22, {"op1": (8, 0), "op2": (4, 0), "res": (2, 0)},
         {"op2": 8 * 16, "res": 7 * 16}, 0),              # 6: $row = fetch -> T7
        (44, {"op1": (2, 0), "op2": (0, 2)}, {"op1": 7 * 16}, 0),  # 7: JMPNZ -> 1
        (62, {"op1": (1, 2)}, {}, 0),                     # 8: RETURN
    ], zvals=[{"type": 6, "str": b"use_row"}, {"type": 6, "str": b"next_row"},
              {"type": 1}], cv={0: "row"})
    emit_region(l, 0, l.thr)
    t = out(l)
    assert t.count("$row = next_row();") == 2  # priming + body-end re-read
    assert "while ($row) {" in t
    assert "use_row($row);" in t


def test_bottom_tested_while_pure_condition_no_priming():
    # pure condition (IS_SMALLER def only): no statements, no re-eval
    l = mk([
        (42, {"op1": (0, 3)}, {}, 0),                     # 0: JMP -> 2 (cond)
        (34, {"op1": (8, 0)}, {}, 0),                     # 1: body: ++$i
        (20, {"op1": (8, 0), "op2": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
        (44, {"op1": (2, 0), "op2": (0, 2)}, {"op1": 7 * 16}, 0),  # JMPNZ -> 1
        (62, {"op1": (1, 1)}, {}, 0),
    ], zvals=[{"type": 4, "a": 10}, {"type": 1}], cv={0: "i"})
    emit_region(l, 0, l.thr)
    t = out(l)
    assert "while ($i < 10) {" in t
    assert "++$i;" in t
    assert t.count("++$i;") == 1  # no duplicate: the cond emits no statement


# ---- break/continue with levels (dawwinci structurer.py:244-250) ----


def _switch_nodes():
    """SWITCH_STRING header + CASE/JMPNZ chain (2 cases) + default + bodies."""
    nodes = [
        (186, {"op1": (8, 0), "op2": (1, 4), "res": UNUSED}, {}, 0),  # 0: header
        (48, {"op1": (8, 0), "op2": (1, 1), "res": (2, 0)}, {"res": 7 * 16}, 0),  # 1: CASE 'a'
        (44, {"op1": (2, 0), "op2": (0, 7)}, {"op1": 7 * 16}, 0),  # 2: JMPNZ -> 6
        (48, {"op1": (8, 0), "op2": (1, 2), "res": (2, 0)}, {"res": 7 * 16}, 0),  # 3: CASE 'b'
        (44, {"op1": (2, 0), "op2": (0, 10)}, {"op1": 7 * 16}, 0),  # 4: JMPNZ -> 9
        (42, {"op1": (0, 9)}, {}, 0),  # 5: default JMP -> 8
        (22, {"op1": (8, 1), "op2": (1, 3)}, {}, 0),  # 6: 'a' body
        (42, {"op1": (0, 11)}, {}, 0),  # 7: 'a' break -> 10
        (22, {"op1": (8, 1), "op2": (1, 3)}, {}, 0),  # 8: default body
        (22, {"op1": (8, 1), "op2": (1, 3)}, {}, 0),  # 9: 'b' body
        (136, {"op1": (1, 0)}, {}, 0),  # 10: post-switch statement (switch end)
        (62, {"op1": (1, 4)}, {}, 0),  # 11: RETURN
    ]
    zvals = [{"type": 6, "str": b"end"}, {"type": 6, "str": b"a"},
             {"type": 6, "str": b"b"}, {"type": 6, "str": b"body"},
             {"type": 7, "str": b"[1'ai6;4;0;1'bi9;4;0;}0;775;0;1;7;"}]
    return nodes, zvals


def test_break_inside_switch():
    nodes, zvals = _switch_nodes()
    l = mk(nodes, zvals=zvals, cv={0: "x", 1: "out"})
    emit_region(l, 0, l.thr)
    t = out(l)
    assert "switch ($x) {" in t
    assert "case 'a':" in t and "case 'b':" in t
    assert "default:" in t
    assert "break;" in t
    assert "$out = 'body';" in t


def test_continue_inside_foreach():
    # foreach body containing a JMP back to the FE_FETCH = continue;
    l = mk([
        (77, {"op1": (8, 0), "res": (2, 0), "op2": (0, 7)}, {"res": 6 * 16}, 0),  # FE_RESET -> 6
        (78, {"op1": (2, 0), "op2": (8, 1), "res": UNUSED}, {"op1": 6 * 16}, 0),  # FE_FETCH
        (136, {"op1": (8, 1)}, {}, 0),               # 2: body echo $v
        (42, {"op1": (0, 2)}, {}, 0),                # 3: JMP -> 1 (continue)
        (136, {"op1": (1, 0)}, {}, 0),               # 4: body tail
        (42, {"op1": (0, 2)}, {}, 0),                # 5: the loop's own back JMP
        (127, {"op1": (2, 0)}, {"op1": 6 * 16}, 0),  # 6: FE_FREE
        (62, {"op1": (1, 1)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"tail"}, {"type": 1}], cv={0: "items", 1: "v"})
    emit_region(l, 0, l.thr)
    t = out(l)
    assert "foreach ($items as $v) {" in t
    assert "continue;" in t
    assert "echo 'tail';" in t  # the body tail stays INSIDE the loop


def test_break_level_two_in_nested_loop():
    from ioncube_re.lift.model import LoopInfo
    l = mk([
        (42, {"op1": (0, 2)}, {}, 0),  # JMP -> 1
        (42, {"op1": (0, 3)}, {}, 0),  # a break-targeting JMP at depth 2
        (62, {"op1": (1, 0)}, {}, 0),
    ], zvals=[{"type": 1}])
    # an inner loop (depth 1) then an outer (depth 2): the JMP targets the
    # OUTER break target -> break 2;
    l.loop_stack.append(LoopInfo(frozenset({1}), frozenset()))  # outer (pushed first)
    l.loop_stack.append(LoopInfo(frozenset({5}), frozenset()))  # inner (innermost last)
    l.jt[1] = 1  # self-adjacent, irrelevant: the loop-exit check fires first
    from ioncube_re.lift.structurer import emit_jmp
    emit_jmp(l, 1, l.thr)
    assert "break 2;" in out(l)


# ---- ternary (dawwinci structurer.py:196-212, test_ternary) ----


def test_ternary():
    # $x = $c ? 'yes' : 'no';
    l = mk([
        (43, {"op1": (8, 0), "op2": (0, 4)}, {}, 0),     # 0: JMPZ $c -> 3
        (31, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),  # 1: QM 'yes'
        (42, {"op1": (0, 5)}, {}, 0),                    # 2: JMP -> 4
        (31, {"op1": (1, 1), "res": (2, 0)}, {"res": 7 * 16}, 0),  # 3: QM 'no'
        (22, {"op1": (8, 1), "op2": (2, 0)}, {"op2": 7 * 16}, 0),  # 4: $x = T7
        (62, {"op1": (1, 2)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"yes"}, {"type": 6, "str": b"no"},
              {"type": 1}], cv={0: "c", 1: "x"})
    emit_region(l, 0, l.thr)
    t = out(l)
    assert "$x = ($c ? 'yes' : 'no');" in t
    assert "if (" not in t


def test_ternary_jmpnz_inverts_condition():
    l = mk([
        (44, {"op1": (8, 0), "op2": (0, 4)}, {}, 0),     # JMPNZ $c -> 3
        (31, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),
        (42, {"op1": (0, 5)}, {}, 0),
        (31, {"op1": (1, 1), "res": (2, 0)}, {"res": 7 * 16}, 0),
        (22, {"op1": (8, 1), "op2": (2, 0)}, {"op2": 7 * 16}, 0),
        (62, {"op1": (1, 2)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"yes"}, {"type": 6, "str": b"no"},
              {"type": 1}], cv={0: "c", 1: "x"})
    emit_region(l, 0, l.thr)
    assert "$x = (!($c) ? 'yes' : 'no');" in out(l)


def test_ternary_multi_node_fetch_arms():
    # `$limit = isset($_REQUEST['limit']) ? $_REQUEST['limit'] : 25;` — the
    # isset-guard lowering: the then arm is FETCH_R+FETCH_DIM_R+QM_ASSIGN
    # (AnnouncementsController getannouncementsAction, the LINT-GATE repro)
    l = mk([
        (89, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),   # FETCH_IS _REQUEST
        (115, {"op1": (2, 0), "op2": (1, 1), "res": (2, 0)},
         {"op1": 7 * 16, "res": 8 * 16}, 0),                        # isset(...) -> T3
        (43, {"op1": (2, 0), "op2": (0, 8)}, {"op1": 8 * 16}, 0),   # JMPZ -> 7
        (80, {"op1": (1, 0), "res": (2, 0)}, {"res": 9 * 16}, 0),   # FETCH_R _REQUEST
        (81, {"op1": (2, 0), "op2": (1, 1), "res": (2, 0)},
         {"op1": 9 * 16, "res": 10 * 16}, 0),                       # FETCH_DIM_R 'limit'
        (31, {"op1": (2, 0), "res": (2, 0)},
         {"op1": 10 * 16, "res": 11 * 16}, 0),                      # QM -> T6
        (42, {"op1": (0, 9)}, {}, 0),                               # JMP -> 8
        (31, {"op1": (1, 2), "res": (2, 0)}, {"res": 11 * 16}, 0),  # QM 25 -> T6
        (22, {"op1": (8, 0), "op2": (2, 0)}, {"op2": 11 * 16}, 0),  # $limit = T6
        (62, {"op1": (1, 3)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"_REQUEST"}, {"type": 6, "str": b"limit"},
              {"type": 4, "a": 25}, {"type": 1}], cv={0: "limit"})
    emit_region(l, 0, l.thr)
    t = out(l)
    assert "$limit = (isset($_REQUEST['limit']) ? $_REQUEST['limit'] : 25);" in t
    assert "if (" not in t
    assert "4294967295" not in t


def test_ternary_multi_node_else_arm():
    # both arms multi-node: then QM, else FETCH_DIM_R+QM into the same slot
    # (UserPackageGateway: `$x = $c ? 'a' : $arr['k'];`)
    l = mk([
        (43, {"op1": (8, 0), "op2": (0, 4)}, {}, 0),                # JMPZ $c -> 3
        (31, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),   # QM 'a'
        (42, {"op1": (0, 6)}, {}, 0),                               # JMP -> 5
        (81, {"op1": (8, 1), "op2": (1, 1), "res": (2, 0)},
         {"res": 8 * 16}, 0),                                       # FETCH_DIM_R $arr['k']
        (31, {"op1": (2, 0), "res": (2, 0)},
         {"op1": 8 * 16, "res": 7 * 16}, 0),                        # QM -> T2
        (22, {"op1": (8, 2), "op2": (2, 0)}, {"op2": 7 * 16}, 0),   # $x = T2
        (62, {"op1": (1, 2)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"a"}, {"type": 6, "str": b"k"},
              {"type": 1}], cv={0: "c", 1: "arr", 2: "x"})
    emit_region(l, 0, l.thr)
    assert "$x = ($c ? 'a' : $arr['k']);" in out(l)


# ---- `?:` JMP_SET full form (dawwinci structurer.py:379-396) ----


def test_jmp_set_elvis():
    # $x = $c ?: 'fallback';
    l = mk([
        (152, {"op1": (8, 0), "res": (2, 0), "op2": (0, 3)}, {"res": 7 * 16}, 0),
        (31, {"op1": (1, 0), "res": (2, 0)}, {"res": 7 * 16}, 0),  # 1: QM 'fallback'
        (22, {"op1": (8, 1), "op2": (2, 0)}, {"op2": 7 * 16}, 0),  # 2: $x = T7
        (62, {"op1": (1, 1)}, {}, 0),
    ], zvals=[{"type": 6, "str": b"fallback"}, {"type": 1}], cv={0: "c", 1: "x"})
    emit_region(l, 0, l.thr)
    assert "$x = ($c ?: 'fallback');" in out(l)


# ---- the jumptable-header switch (the Blesta IS_EQUAL+JMPNZ form) ----


def test_switch_header_is_equal_chain():
    """The Blesta generation's form: SWITCH_STRING header + IS_EQUAL/JMPNZ
    chain (license.php setError's shape)."""
    zvals = [{"type": 1}, {"type": 6, "str": b"a"}, {"type": 6, "str": b"b"},
             {"type": 6, "str": b"body"},
             {"type": 7, "str": b"[1'ai6;4;0;1'bi9;4;0;}0;775;0;1;7;"}]
    nodes = [
        (186, {"op1": (8, 0), "op2": (1, 4), "res": UNUSED}, {}, 0),  # 0: header
        (18, {"op1": (8, 0), "op2": (1, 1), "res": (2, 0)}, {"res": 7 * 16}, 0),  # IS_EQUAL 'a'
        (44, {"op1": (2, 0), "op2": (0, 7)}, {"op1": 7 * 16}, 0),  # 2: JMPNZ -> 6
        (18, {"op1": (8, 0), "op2": (1, 2), "res": (2, 0)}, {"res": 7 * 16}, 0),  # IS_EQUAL 'b'
        (44, {"op1": (2, 0), "op2": (0, 10)}, {"op1": 7 * 16}, 0),  # 4: JMPNZ -> 9
        (42, {"op1": (0, 9)}, {}, 0),  # 5: default JMP -> 8
        (22, {"op1": (8, 1), "op2": (1, 3)}, {}, 0),  # 6: 'a' body
        (42, {"op1": (0, 11)}, {}, 0),  # 7: break -> 10
        (22, {"op1": (8, 1), "op2": (1, 3)}, {}, 0),  # 8: default body
        (22, {"op1": (8, 1), "op2": (1, 3)}, {}, 0),  # 9: 'b' body
        (136, {"op1": (1, 0)}, {}, 0),  # 10: post-switch statement (switch end)
        (62, {"op1": (1, 4)}, {}, 0),  # 11: RETURN
    ]
    l = mk(nodes, zvals=zvals, cv={0: "status", 1: "out"})
    emit_region(l, 0, l.thr)
    t = out(l)
    assert "switch ($status) {" in t
    assert "case 'a':" in t and "case 'b':" in t
    assert "default:" in t
    assert "break;" in t
    assert "IS_EQUAL" not in t and "opcode 18)" not in t


def test_switch_header_degrades_without_chain():
    # header alone (no chain, no usable table): the old bookkeeping behavior
    l = mk([(186, {"op1": (8, 0), "op2": (1, 0), "res": UNUSED}, {}, 0),
            (62, {"op1": (1, 1)}, {}, 0)],
           zvals=[{"type": 7, "str": b"not-a-table"}, {"type": 1}], cv={0: "x"})
    emit_node(l, 0, l.thr)
    assert "switch" not in out(l)
    assert l.bookkept == 1


def test_switch_jumptable_fallback_without_chain():
    """The chain did not reconstruct, but the op2 table carries the pairs:
    the table IS the chain (the jump-table repair — the Blesta-generation
    tables hold node targets directly)."""
    # both table entries target node 2 (the shared fallthrough body)
    l = mk([(186, {"op1": (8, 0), "op2": (1, 0), "res": UNUSED}, {}, 0),
            (136, {"op1": (1, 1)}, {}, 0),   # 1: skipped filler
            (136, {"op1": (1, 1)}, {}, 0),   # 2: the case body
            (62, {"op1": (1, 2)}, {}, 0)],
           zvals=[{"type": 7, "str": b"[1'ai2;4;0;1'bi2;4;0;}0;775;0;1;7;"},
                  {"type": 6, "str": b"end"}, {"type": 1}], cv={0: "x"})
    emit_node(l, 0, l.thr)
    t = out(l)
    assert "switch ($x) {" in t
    assert "case 'a':" in t and "case 'b':" in t


# ---- --valid-php: the goto-label fallback ----


def test_valid_php_goto_fallback():
    # an unstructurable forward JMP: comment by default, goto + label in
    # --valid-php mode
    nodes = [
        (42, {"op1": (0, 2)}, {}, 0),        # 0: JMP -> 1 (skip one node)
        (136, {"op1": (1, 0)}, {}, 0),       # 1: skipped statement
        (136, {"op1": (1, 0)}, {}, 0),       # 2: landing
        (62, {"op1": (1, 1)}, {}, 0),
    ]
    l = mk(nodes, zvals=[{"type": 6, "str": b"x"}, {"type": 1}])
    emit_node(l, 0, l.thr)
    assert "/* n0: JMP -> n1 */" in out(l)
    l2 = mk(nodes, zvals=[{"type": 6, "str": b"x"}, {"type": 1}], valid_php=True)
    emit_region(l2, 0, l2.thr)
    t = out(l2)
    assert "goto label_1;" in t
    assert "label_1:" in t
    assert "/* n0: JMP" not in t


# ---- the foreach key-in-temp fold (dawwinci structurer.py:469-490) ----


def test_foreach_key_in_temp_fold():
    # FE_FETCH delivers the key in a temp; the body's first op is
    # ASSIGN $k, T(key) — fold into the header
    l = mk([
        (77, {"op1": (8, 0), "res": (2, 0), "op2": (0, 7)}, {"res": 6 * 16}, 0),  # FE_RESET -> 6
        (78, {"op1": (2, 0), "op2": (8, 2), "res": (2, 0)},
         {"op1": 6 * 16, "res": 7 * 16}, 0),  # FE_FETCH: value CV2, key T7
        (22, {"op1": (8, 1), "op2": (2, 0)}, {"op2": 7 * 16}, 0),  # 2: $k = T7
        (136, {"op1": (8, 1)}, {}, 0),        # 3: echo $k
        (42, {"op1": (0, 2)}, {}, 0),         # 4: back JMP -> 1
        (127, {"op1": (2, 0)}, {"op1": 6 * 16}, 0),  # 5: FE_FREE (exit=6)
        (62, {"op1": (1, 0)}, {}, 0),
    ], zvals=[{"type": 1}], cv={0: "map", 1: "k", 2: "v"})
    emit_node(l, 0, l.thr)
    assert "foreach ($map as $k => $v) {" in out(l)
    assert "tmp" not in out(l).lower()


# ---- corpus: the patterns on real wires ----


@requires_workspace
def test_corpus_while_priming_taxgateway():
    """getTaxByUserId: `while ($vat = $userid->fetch())` lifts with the
    priming read + the body-end re-read (M5C-LIFTER §5.6's commented
    back-edge pattern)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/modules/billing/models/TaxGateway.php")
    t = r["text"]
    assert t.count("$vat = $userid->fetch();") == 2
    assert "while ($vat) {" in t
    assert "loop back-edge) */" not in t or "JMPNZ" not in t


@requires_workspace
def test_corpus_switch_seterror_blesta():
    """license.php setError: the jumptable header + IS_EQUAL chain
    reconstructs as the real switch (the six nested `if (!($T3))` of the
    pre-refactor output)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{WORK}/corpus/blesta/blesta/app/models/license.php")
    t = r["text"]
    assert "switch ($status) {" in t
    assert "case 'invalid_location':" in t
    assert "case 'unsupported_version':" in t
    assert "$status = 'The license is not valid for this version of the system.';" in t
    assert "if (!($T3))" not in t


@requires_workspace
def test_corpus_ternary_in_array_literal():
    """TaxGateway parseTaxRule: `($data['vat'] == 1 ? true : false)` folds
    into the array literal (the empty if/else arms vanish)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/modules/billing/models/TaxGateway.php")
    t = r["text"]
    assert "'vat' => ($data['vat'] == 1 ? true : false)" in t
    assert "'allcountries' => ($data['countryiso'] == '_ALL' ? true : false)" in t


@requires_workspace
def test_corpus_break_in_switch():
    """Action.php setUserLastView: the case-exit JMPs render break; (the
    default clause renders too)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/library/CE/Controller/Action.php")
    t = r["text"]
    assert "switch ($concat) {" in t
    assert "default:" in t
    assert "break;" in t
    assert "case 'support|viewtickets':" in t


@requires_workspace
def test_valid_php_flag_stays_off_by_default():
    """The goto-label fallback is opt-in: default output keeps the comment
    policy (the documented decision — DAWWINCI-DIFF §5.3 recommendation)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/library/CE/Controller/Action.php")
    assert "goto label_" not in r["text"]
    rv = lift_file(f"{CE}/library/CE/Controller/Action.php", valid_php=True)
    # valid-php mode does not crash and produces SOME output; the corpus
    # files lift fully-structured so goto may not appear — the flag only
    # changes the irreducible-flow fallback
    assert "<?php" in rv["text"]
