"""The lifter's shared vocabulary: Node, Operand, Component, LiftContext.

The wire layer (wire.parse_wire) is frozen and speaks dicts; this module is
the lift-side adapter — ``Node.from_wire`` turns a parsed node dict into a
dataclass once, at context build, so every lift module speaks the same typed
vocabulary. The parse result ``r`` itself is kept around untouched (gt
cross-checks and signature extraction still read it).

LiftContext carries the mutable state one component's lift needs: the opcode
map with the anti-tamper normalizations (the +2 garble, the jump-target
calibration, the +4 VAR-read slot shifts), the temp def/use/expr registry,
the output sink, and the node accounting. Everything else in lift/ is
functions over (ctx, i, end) — the walker (emitter.py), the control-flow
shapers (structurer.py, loops.py), the expression collectors (collectors.py)
and the opcode families (handlers/).

Behavior contract: byte-identical to the pre-refactor IclLifter (the
analysis passes below are its __init__ verbatim, plus the loop_stack /
goto-target state the structurer upgrades need). The three documented
wire ABI facts each live in exactly ONE place:

  * the +2 anti-tamper garble table — ``_ungarble`` below, extended by the
    SWITCH_LONG/SWITCH_STRING pair;
  * the CV-slot +5 rule — operand.py ``OperandRenderer.ex`` (the x86_64
    ABI: slot numbering starts at execute_data's 5 slots, loader-verified);
  * the DO-node stopping point — collectors.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..container import u32

from .analysis import analyze


@dataclass(frozen=True)
class Operand:
    """One operand entry of a node (wire.py's (type, raw) tuple)."""

    kind: int  # 1=const zval, 2=TMP, 4|2=VAR read, 8=CV, 0=unused/ext
    raw: int  # const zval index / CV index / marker value

    @property
    def is_temp(self) -> bool:
        return bool(self.kind & 6)


@dataclass
class Node:
    i: int
    ext: int = 0
    lineno: int = 0
    ent: dict[str, Operand] = field(default_factory=dict)
    op1: int = 0  # raw slot encodings (the wire's conv values)
    op2: int = 0
    res: int = 0
    trueop: int | None = None
    final: int | None = None
    sigok: bool = False

    @classmethod
    def from_wire(cls, d: dict) -> Node:
        return cls(
            i=d["i"],
            ext=d.get("ext", 0),
            lineno=d.get("lineno", 0),
            ent={k: Operand(*v) for k, v in d.get("ent", {}).items()},
            op1=d.get("op1", 0),
            op2=d.get("op2", 0),
            res=d.get("res", 0),
            trueop=d.get("trueop"),
            final=d.get("final"),
            sigok=d.get("sigok", False),
        )

    def opnd(self, which: str) -> Operand | None:
        return self.ent.get(which)


@dataclass
class Component:
    """One lifted unit: a wire, its parse result, its label and metadata."""

    wire: bytes
    r: dict  # the parse_wire result (frozen contract, dicts)
    label: str
    meta: dict  # isFn / fnName / cv / recSeeds / classDepth ...


@dataclass
class LoopInfo:
    """A structured loop/switch being emitted — drives break/continue."""

    break_targets: frozenset[int]
    continue_targets: frozenset[int]


@dataclass
class LiftContext:
    wire: bytes
    r: dict
    nodes: list[Node]
    zvals: list[dict]
    thr: int
    meta: dict

    # component identity
    lc: int
    numArgs: int
    isMain: bool
    cv: dict[int, str]
    fnName: str | None
    opSrc: str

    # analysis state (built once)
    op: dict[int, int | None] = field(default_factory=dict)
    jt: dict[int, int] = field(default_factory=dict)
    feExit: dict[int, int] = field(default_factory=dict)
    effSlot: dict[str, int] = field(default_factory=dict)
    tempDef: dict[int, int] = field(default_factory=dict)
    tempUses: dict[int, list[int]] = field(default_factory=dict)
    tempExpr: dict[int, str] = field(default_factory=dict)
    tryBlocks: list[tuple[int, int]] = field(default_factory=list)

    # emission state
    out: list[str] = field(default_factory=list)
    idp: int = 1
    curLine: int = -1
    rope: list[str | None] = field(default_factory=list)
    condOv: dict[int, str] = field(default_factory=dict)
    silence: list[set[int]] = field(default_factory=list)
    acct: set[int] = field(default_factory=set)
    emitted: int = 0
    bookkept: int = 0
    masked: int = 0
    unknown: int = 0

    # structurer-upgrade state
    loop_stack: list[LoopInfo] = field(default_factory=list)
    valid_php: bool = False  # --valid-php: goto-label fallback mode
    debug: bool = False  # --debug: line markers + node-accounting comments
    goto_targets: set[int] = field(default_factory=set)
    labels_emitted: set[int] = field(default_factory=set)
    # do-while edges: body start -> the conditional back-edge node (first
    # such edge wins; the precomputed map keeps the region pre-scan O(1))
    dw_edges: dict[int, int] = field(default_factory=dict)
    # `for` init nodes: ASSIGN CV=const immediately followed by the loop
    # entry JMP whose bottom-tested shape carries the same CV as init and
    # increment (loops.bottom_tested_while renders the folded header)
    forInit: set[int] = field(default_factory=set)

    render: object = None  # operand.OperandRenderer, attached in build()

    # ---- construction ----

    @classmethod
    def build(cls, wire: bytes, r: dict, meta: dict | None = None) -> LiftContext:
        from .operand import OperandRenderer

        meta = meta or {}
        ctx = cls(
            wire=wire,
            r=r,
            nodes=[Node.from_wire(d) for d in r["nodes"]],
            zvals=r["zvals"],
            thr=r["thr"],
            meta=meta,
            lc=u32(r["hdr"], 0x28),
            numArgs=u32(r["hdr"], 0x14),
            isMain=r["fnrec"] is None and not meta.get("isFn"),
            cv=meta.get("cv", {}),
            fnName=meta.get("fnName"),
            opSrc=meta.get("opSrc", "wire-only"),
        )
        ctx.render = OperandRenderer(ctx)
        analyze(ctx)
        return ctx

    def name(self) -> str:
        return (
            self.fnName
            if self.fnName is not None
            else ("<main>" if self.isMain else "<fn>")
        )

    # ---- emission helpers (the shared sink + accounting) ----

    def w(self, s: str) -> None:
        self.out.append("    " * self.idp + s + "\n")

    def line(self, n: Node) -> None:
        if self.debug and n.lineno > 0 and n.lineno != self.curLine:
            self.curLine = n.lineno
            self.w(f"// line {n.lineno}")

    def bk(self, i: int) -> None:
        if self.op.get(i) is not None and i not in self.acct:
            self.bookkept += 1
            self.acct.add(i)

    def inlinable(self, slot: int, use_node: int) -> bool:
        if slot not in self.tempExpr or slot not in self.tempDef:
            return False
        uses = self.tempUses.get(slot, [])
        op = self.op.get(use_node)
        if op in _INIT_CALL:
            # the method-call receiver: INIT op1 is in _SKIPUSE (the
            # DO..INIT pair is one statement), so the slot may carry no
            # registered use at all — the collector reads it exactly once
            # through this node. Inline when nothing else reads it either.
            if uses not in ([], [use_node]):
                return False
        elif op == 137:
            # OP_DATA: the assign's value operand is read through the
            # unregistered data node (ASSIGN_DIM..OP_DATA pair). Inline when
            # the def range holds nothing but the pair partner.
            if uses:
                return False
            d = self.tempDef[slot]
            if d >= use_node:
                return False
            for i in range(d + 1, use_node):
                if i != use_node - 1 and (
                    self.op[i] not in _PLUMBING and self.op[i] not in _PURE
                ):
                    return False
            return True
        elif len(uses) != 1 or uses[0] != use_node:
            return False
        d = self.tempDef[slot]
        if d >= use_node:
            # forward read: the read precedes its def node in walk order —
            # the expression is not yet registered when this renders, so it
            # cannot inline; def_temp stages the statement at the first use
            # node instead (pendingStmt)
            return False
        for i in range(d + 1, use_node):
            if self.op[i] not in _PLUMBING and self.op[i] not in _PURE:
                return False
        return True

    def temp_name(self, slot: int, kind: int) -> str:
        # the reference name an operand with this slot/kind renders as
        # (operand.ex's "$V"/"$T" + slot-5 rule)
        return ("$V" if kind & 4 else "$T") + str(slot - 5)

    def def_temp(self, n: Node, expr: str | None, i: int) -> int:
        from .operand import unwrap

        if expr is None:
            self.bookkept += 1
            return i + 1
        e = n.ent.get("res")
        if e and (e.kind & 6):
            slot = n.res // 16
            uses = self.tempUses.get(slot, [])
            forward = bool(uses) and min(uses) < i
            if len(uses) > 1 or forward:
                # a multi-read temp keeps a named definition statement: the
                # references render the same $Tn/$Vn and every read sees the
                # variable (same contract as the multi-read DO_FCALL/NEW
                # result). A forward read (use node < def node) keeps the
                # statement at the def position too: the VM's temp slot is
                # NULL until this node writes it, and the earlier read sees
                # exactly that null — render order matches execution order
                self.line(n)
                self.w(self.temp_name(slot, e.kind) + " = " + unwrap(expr) + ";")
            self.tempExpr[slot] = expr
            self.emitted += 1
            return i + 1
        self.line(n)  # no result slot: bare statement
        self.w(unwrap(expr) + ";")
        self.emitted += 1
        return i + 1

    def cv_name(self, i: int) -> str:
        return "$" + self.cv[i] if i in self.cv else f"$CV{i}"


# the method-call-init opcodes (analysis._INIT): the INIT..DO pair renders
# as one statement, so INIT op1 (the receiver) is excluded from the use
# registration — inlinable() special-cases it via this mirror set
_INIT_CALL = frozenset({59, 61, 69, 112, 113, 118, 128})


# plumbing + pure sets for the single-use temp inlining decision —
# the $pure list is load-bearing: without it every CONCAT chain broke at
# the first FETCH_CONSTANT link. CHECK_FUNC_ARG(100) joins the plumbing:
# by-ref arg glue between NEW/INIT and its SENDs broke NEW+ASSIGN inlining
# ($packagegateway = $V14 — EmailsController n10 sits between the NEW
# def and the ASSIGN read).
_PLUMBING = frozenset(
    {
        59,
        61,
        69,
        112,
        113,
        118,
        128,
        50,
        65,
        66,
        67,
        106,
        116,
        117,
        119,
        120,
        165,
        60,
        129,
        130,
        131,
        68,
        100,
        137,
        124,
        183,
        # the @-silence pair wraps the expression it guards: glue between
        # the call def and the ASSIGN read ($val = @ini_set(...) —
        # getMemoryLimit)
        57,
        58,
        # BIND_LEXICAL + the ktab-garbled variant: pure glue
        # between the DECLARE_LAMBDA def and its ASSIGN use
        180,
        182,
    }
)
_PURE = frozenset(
    list(range(1, 22))
    + [
        31,
        51,
        52,
        53,
        99,
        71,
        72,
        109,
        114,
        115,
        121,
        123,
        138,
        148,
        154,
        169,
        170,
        188,
        191,
    ]
    + list(range(80, 99))
    + list(range(173, 179))
)


__all__ = ["Component", "LoopInfo", "LiftContext", "Node", "Operand"]
