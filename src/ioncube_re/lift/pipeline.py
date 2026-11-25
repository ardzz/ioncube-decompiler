"""The file-level lift pipeline: encoded file -> component stream -> main
wire + sub-function wires -> opcode resolution -> per-component walk ->
the PHP listing (plus the gt cross-check wiring).

Pure assembly: wires.py/sources.py find the wires and their opcode sources,
emitter walks each component; this module owns the ordering, the class
skeletons and the component labels.
"""

from __future__ import annotations

import os
import re

from ..container import (
    decrypt_file,
    layer_a,
    prod_blob_locate,
    prod_chunks,
    prod_container,
    u32,
)
from ..crypto.layerb import EVAL_KEY, component_decrypt
from ..stream import prod_decode_file, stream_of_file
from ..wire import gt_check, gt_sections, parse_wire
from .signature import arg_names, arg_specs, cv_names, fn_name_of, param_list
from .sources import best_pair, capture_pairs, m5_sample_dir, offline_parse
from .wires import (
    class_like_names,
    class_name_hint,
    classrec_strings,
    desc_strings,
    pool_strings,
    record_seeds,
    scan_wires,
    tail_doccomment,
)
from .emitter import walk_component
from .model import LiftContext

_IDENT = re.compile(r"^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$")

# PHP builtins that collide as free-function names (`function extract()` is
# a compile error at top level; legal as a class method)
_PHP_RESERVED_FNS = frozenset(
    {
        "extract",
        "compact",
        "pack",
        "unpack",
        "reset",
        "current",
        "next",
        "prev",
        "end",
        "key",
        "list",
        "isset",
        "unset",
        "empty",
        "echo",
        "print",
        "die",
        "exit",
        "eval",
    }
)


class PipelineError(Exception):
    pass


def _declared_class(r: dict) -> tuple[str, str | None] | None:
    """(class, parent) from an opcode-resolved wire's DECLARE_CLASS node.

    The eval skeleton otherwise guesses the class from descriptor records,
    which on some encoder generations name the *parent* (and can yield a
    self-extension). DECLARE_CLASS op1/op2 carry the authoritative FQCNs;
    they are string zvals on both operand slots.
    """
    for n in r.get("nodes", []):
        op = n.get("trueop")
        if op is None:
            op = n.get("final")
        if op not in (144, 145):  # DECLARE_CLASS, DECLARE_CLASS_DELAYED
            continue

        def name(which: str) -> str | None:
            e = n.get("ent", {}).get(which)
            if not e or e[0] != 1 or e[1] >= len(r.get("zvals", [])):
                return None
            s = r["zvals"][e[1]].get("str")
            return s.decode("latin-1") if s else None

        cls = name("op1")
        if cls:
            return cls, name("op2")
    return None


def lift_file(
    path: str,
    chunk: int = 1,
    arena=None,
    ktab=None,
    gt=None,
    auto: bool = True,
    m5dir: str | None = None,
    valid_php: bool = False,
    debug: bool = False,
    ierg: int | None = None,
) -> dict:
    """Lift one encoded file. Returns {'text': str, 'gt': [lines], 'stderr': [lines]}.

    ierg overrides the keytable mask derived from the main blob. License-bound
    (dynamic-key) files do not carry their real mask in the file; an operator
    who knows it (from a known-good decode) can supply it here.

    Raises PipelineError on decode/parse failure (the PHP tool exits 2 there)."""
    stderr: list[str] = []
    with open(path, "rb") as f:
        data = f.read()
    isProd = data[:12] == b"<?php //ICB0"
    # the 00447 generation's method descriptors carry method/param/local
    # names (not class records); other eval generations keep class groups
    disableRecClasses = data.startswith(b"<?php //00447")
    classFile = os.path.basename(path).endswith((".class.php", ".class"))

    if isProd:
        pr = prod_decode_file(path, chunk)
        if not pr["chunks"]:
            raise PipelineError(f"no chunk {chunk}")
        stream = pr["chunks"][0]["stream"]
        mode = f"production, chunk {chunk}"
    else:
        sr = stream_of_file(path)  # raises on chain failure
        stream = sr["stream"]
        mode = "eval"

    loc = prod_blob_locate(stream)
    if loc is None:
        raise PipelineError("component ciphertext not found")
    boff, bsize, blob, bmethod = loc
    mainWire = component_decrypt(blob, EVAL_KEY)
    mainR = parse_wire(mainWire)
    if not mainR["chk"] or mainR["thr"] < 1:
        raise PipelineError("main component failed checksum")

    mainDesc = desc_strings(stream, 0x40, boff)
    subs = scan_wires(stream, boff + bsize)
    prevEnd = boff + bsize
    subMeta = []
    for off, size, r in subs:
        rec = desc_strings(stream, prevEnd, off - 4)
        # the descriptor stores the DECLARED record size (u32 before the
        # wire), which covers any trailing nested-record region; the seed
        # lookup must match that word, not the wire end scan_wires returns
        decl = u32(stream, off - 4) if off >= 4 else size
        subMeta.append(
            (
                r,
                rec,
                stream[off : off + size],
                off,
                record_seeds(stream, prevEnd, off - 4, decl),
            )
        )
        prevEnd = off + size
    # nested sub-wires: the eval wire's [sf] section lives in the DECRYPTED
    # main wire's tail (gfuncs: sf=3 -> 3 closures at 1801/2292/2888, each
    # with its own [size][seedA][seedB] record in the same tail). Production
    # wires walk to EOF, so this scan is a no-op there.
    if mainR["end"] < len(mainWire):
        nested = scan_wires(mainWire, mainR["end"])
        prevN = mainR["end"]
        for off, size, r in nested:
            rec = desc_strings(mainWire, prevN, off - 4)
            decl = u32(mainWire, off - 4) if off >= 4 else size
            subMeta.append(
                (
                    r,
                    rec,
                    mainWire[off : off + size],
                    off,
                    record_seeds(mainWire, prevN, off - 4, decl),
                )
            )
            prevN = off + size

    # opcode capture pool: m5 auto-discovery + explicit --arena/--ktab
    captureDirs: list[str] = []
    if auto and not isProd:
        d = m5_sample_dir(mainWire, m5dir or os.environ.get("IONCUBE_RE_M5_DIR", ""))
        if d is not None:
            captureDirs.append(d)
            stderr.append(
                "lift: m5 capture match: %s (arena/ktab reuse)" % os.path.basename(d)
            )
    pairPool = capture_pairs(captureDirs)
    if arena and ktab:
        pairPool.insert(0, (arena, ktab))

    # offline keytable inputs: ierg + X from the main blob
    offlineIerg = None
    offlineX = 6 if isProd else 2
    if isProd:
        _fields, chunks = prod_chunks(path)
        cont = prod_container(chunks[chunk - 1], "lift")
        mb = layer_a(cont["blob"], cont["seed"])
        # mainblob: [ver@0][f@4][f@8][A@0xc][str_len@0x10][str bytes][IERG][namekey]
        # [X if v>5] — ierg/X sit at 0x14/0x1c + str_len (eval and most
        # production generations carry str_len=0; some carry a 16-byte
        # string -> +0x10).
        sl = u32(mb, 0x10)
        offlineIerg = u32(mb, 0x14 + sl)
        offlineX = u32(mb, 0x1C + sl)
        if offlineX > 64:
            offlineX = 6  # implausible X (8.1-target chunks) -> prod default
    else:
        dr = decrypt_file(path)  # validates adler+MD4
        sl = u32(dr["plain"], 0x10)
        offlineIerg = u32(dr["plain"], 0x14 + sl)
        offlineX = u32(dr["plain"], 0x1C + sl)
        if offlineX > 64:
            offlineX = 2  # implausible X -> the eval default
    if ierg is not None:
        # explicit override (dynamic-key/license-bound files store a decoy
        # mask in the main blob; the real one is license-derived)
        offlineIerg = ierg
    mainSeeds = (u32(stream, 0x08), u32(stream, 0x0C))

    out: list[str] = ["<?php\n"]
    if debug:
        out.append(
            f"// lift: {os.path.basename(path)} — mode: {mode} — "
            f"{1 + len(subMeta)} component(s)\n"
        )
        if isProd:
            out.append(
                "// production chain (ICB0->chunk->container->frame codec->deflate->component->layer-B) verified offline\n"
            )

    gtsecs = gt_sections(open(gt).read()) if gt else None
    gtkeys = list(gtsecs) if gtsecs else []
    gtIdx = 0
    gt_report: list[str] = []

    def liftOne(wire: bytes, r: dict, meta: dict, label: str):
        nonlocal gtIdx
        if pairPool:
            best = best_pair(wire, pairPool)
            if best is not None:
                r = best[0]
                meta["opSrc"] = best[1]
        if "opSrc" not in meta and offlineIerg is not None:
            seeds = mainSeeds if not meta.get("isFn") else meta.get("recSeeds")
            der = offline_parse(wire, seeds, offlineIerg, offlineX, not isProd)
            if der is not None:
                # the offline resolver supersedes the arena path: the wD0
                # table map is complete (669 handlers) where HANDLER2OP
                # (the arena trueop source) names only a subset (gflow
                # main: arena 42/71 vs offline 71/71 opcodes resolved)
                r = der[0]
                meta["opSrc"] = der[1]
        meta.setdefault("opSrc", "wire-only")
        # keep the opcode-resolved parse: the eval class skeleton reads the
        # DECLARE_CLASS operands out of it (main component only)
        meta["resolved"] = r
        ctx = LiftContext.build(wire, r, meta)
        ctx.valid_php = valid_php
        ctx.debug = debug
        if debug:
            out.append(
                f"// ===== component: {label} — thr={r['thr']} nodes, "
                f"opcodes: {meta['opSrc']} =====\n"
            )
        if meta.get("isFn"):
            cd = 1 if meta.get("classDepth") else 0
            fn = ctx.fnName if ctx.fnName is not None else "{fn}"
            specs, ret = arg_specs(r)
            ctx.meta["hasRetType"] = bool(ret) and ret != "void"
            # a PHP function name cannot be namespaced: `function A\B()` is a
            # parse error, keep the leaf (`Ns\...\{closure}` -> `{closure}`)
            if "\\" in fn:
                fn = fn.rsplit("\\", 1)[-1]
            if fn in _PHP_RESERVED_FNS and not cd:
                # a free function shadowing a PHP builtin (`extract`) is a
                # compile error — suffix keeps the listing parseable
                fn = fn + "_"
            sig = ", ".join(param_list(ctx))
            retPart = f": {ret}" if ret else ""
            if fn.endswith("{closure}"):
                # an anonymous function's name record holds the literal
                # "{closure}" (production: namespaced `Ns\...\{closure}`) —
                # emitting it as an identifier is invalid PHP
                out.append("    " * cd + f"function ({sig}){retPart} {{\n")
            else:
                # method modifiers: visibility bits + ZEND_ACC_STATIC (0x10)
                # from the wire's fn_flags; free functions take none
                mods = ""
                if cd:
                    flags = r.get("fn", 0)
                    vis = {1: "public", 2: "protected", 4: "private"}.get(
                        flags & 0x7, "public"
                    )
                    mods = vis + (" static" if flags & 0x10 else "") + " "
                out.append("    " * cd + f"{mods}function {fn}({sig}){retPart} {{\n")
            ctx.idp = cd + 1
        else:
            ctx.idp = 1 if meta.get("classDepth") else 0
        out.append(walk_component(ctx))
        if meta.get("isFn"):
            out.append("    " * (1 if meta.get("classDepth") else 0) + "}\n\n")
        if gtsecs and gtIdx < len(gtkeys):
            sec = gtkeys[gtIdx]
            ok, tot, extra, miss = gt_check(r["nodes"], gtsecs[sec])
            line = (
                "  gt %-24s opcode match %d/%d gt oplines (+%d rule-expanded nodes, thr=%d)%s"
                % (sec, ok, len(gtsecs[sec]), extra, tot, " MISSES:" if miss else "")
            )
            gt_report.append(line)
            for m in miss:
                gt_report.append("      " + m)
            gtIdx += 1

    # ---- main component ----
    mainMeta: dict = {"isFn": False}
    if mainR["fnrec"] is not None:
        mainMeta["fnName"] = fn_name_of(mainR)
    # the main-component CV names: the descriptor strings ARE the CV names
    # in slot order — index them (a bare list would break `i in cv`
    # membership in cv_name, falling back to $CVn); production reads the
    # wire pool like the sub-components do
    mainMeta["cv"] = (
        cv_names(mainR, "prod", [], is_fn=False)
        if isProd
        else (
            {k: nm for k, nm in enumerate(mainDesc)}
            if mainDesc
            else cv_names(mainR, "eval", [])
        )
    )

    # ---- closure-body pre-render: the {closure} nested sub-wires render as
    # full (sig, ret, stmts) texts consumed by the declaring component's
    # DECLARE_LAMBDA placeholder; source order matches the nested order ----
    closureBodies: list[tuple[str, str, str]] = []
    if mainR["end"] < len(mainWire):
        prevN = mainR["end"]
        for off, size, r in scan_wires(mainWire, mainR["end"]):
            if fn_name_of(r) == "{closure}":
                decl = u32(mainWire, off - 4) if off >= 4 else size
                seeds = record_seeds(mainWire, prevN, off - 4, decl)
                der = offline_parse(
                    mainWire[off : off + size],
                    seeds,
                    offlineIerg,
                    offlineX,
                    not isProd,
                )
                if der is not None:
                    r = der[0]
                cm: dict = {
                    "isFn": True,
                    "cv": cv_names(r, "eval", []),
                }
                cctx = LiftContext.build(mainWire[off : off + size], r, cm)
                cctx.valid_php = valid_php
                cctx.idp = 1
                body = walk_component(cctx).strip("\n")
                _specs, ret = arg_specs(r)
                sig = ", ".join(param_list(cctx))
                closureBodies.append((sig, ret or "", body))
            prevN = off + size
    mainMeta["closureBodies"] = closureBodies

    # ---- outer sub-wire closures ----
    # Method bodies live in the outer sub-wire stream, and their {closure}
    # components follow the declaring method in source order.  Render them
    # lazily: a DECLARE_LAMBDA site consumes the next component, so a
    # closure body's own nested sites consume the nested components that
    # follow it (depth-first source order).
    outerClosures: list[tuple[dict, bytes, tuple]] = [
        (r, wirebytes, recSeeds)
        for (r, _rec, wirebytes, _off, recSeeds) in subMeta
        if fn_name_of(r) is not None and fn_name_of(r).endswith("{closure}")
    ]

    def nextOuterClosure():
        if not outerClosures:
            return None
        r, wirebytes, recSeeds = outerClosures.pop(0)
        try:
            der = offline_parse(
                wirebytes, recSeeds, offlineIerg, offlineX, not isProd
            )
            rr = der[0] if der is not None else r
            cm: dict = {
                "isFn": True,
                "cv": cv_names(rr, "eval", []),
                "closure_at": nextOuterClosure,
            }
            cctx = LiftContext.build(wirebytes, rr, cm)
            cctx.valid_php = valid_php
            cctx.idp = 1
            body = walk_component(cctx).strip("\n")
            _specs, ret = arg_specs(rr)
            sig = ", ".join(param_list(cctx))
            return (sig, ret or "", body)
        except Exception:
            return None

    mainMeta["closure_at"] = nextOuterClosure

    liftOne(
        mainWire,
        mainR,
        mainMeta,
        f"function {fn_name_of(mainR)}" if mainR["fnrec"] is not None else "main",
    )

    # ---- production class skeleton ----
    prodClassOpen = False
    prodQueue: list[tuple[str, str | None]] = []
    prodSeen: set[str] = set()
    prodSerial = 0
    prodQueueNames: list[str] = []
    if isProd:
        tailStart = boff + bsize
        if (
            len(stream) > tailStart + 5
            and stream[tailStart : tailStart + 2] == b"\x00\x00"
            and stream[tailStart + 4] == 2
        ):
            rec = classrec_strings(stream, tailStart, tailStart + 0x60)
            ps = [s.decode("latin-1") for s in pool_strings(mainR["pool"])]
            cls = rec[0] if rec else (ps[1] if len(ps) > 1 else "?")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\]*", cls):
                # the fixed 0x60 window and the pool can both miss the class
                # record (an anonymous-class or property record can precede
                # it); the record whose leaf matches this file's basename is
                # the declaring class
                leaf = os.path.basename(path)
                if leaf.endswith(".php"):
                    leaf = leaf[:-4]
                hint = class_name_hint(stream, tailStart, leaf)
                if hint is not None:
                    cls = hint
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\]*", cls):
                # unrecoverable class name: no skeleton (the bare
                # `class ? {` form is a parse error); the components emit
                # as free functions
                cls = None
                parent = None
            else:
                parent = None
                if (
                    len(rec) > 1
                    and rec[1] != cls
                    and re.search("[A-Z]", rec[1])
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\]*", rec[1])
                ):
                    parent = rec[1]
                elif (
                    len(ps) > 0
                    and ps[0] != cls
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\]*", ps[0])
                ):
                    parent = ps[0]
            if cls is not None:
                # a parent recovered from the pool can be the class itself in
                # a different case (Captcha extends whmcs\utility\captcha) —
                # extending yourself is not allowed, fall back to a base
                if parent is not None and parent.lower().lstrip(
                    "\\"
                ) == cls.lower().lstrip("\\"):
                    parent = None
                # a namespaced class cannot be declared FQ (`class A\B` is a
                # syntax error): split off a `namespace` declaration, the bare
                # class name, and a leading-backslash FQ parent
                ns = None
                if "\\" in cls:
                    ns, cls = cls.rsplit("\\", 1)
                if ns:
                    out.append(f"\nnamespace {ns};\n")
                if parent and "\\" in parent and not parent.startswith("\\"):
                    parent = "\\" + parent
                doc = tail_doccomment(stream, tailStart)
                if doc is not None:
                    out.append("\n" + doc + "\n")

                def _open_class(leaf: str, ext: str | None = None) -> None:
                    # no invented parent: when no parent was recovered the
                    # class stands alone (a body using parent:: degrades
                    # visibly instead of silently extending \stdClass,
                    # which would change get_parent_class()/instanceof)
                    out.append(
                        f"\nclass {leaf}"
                        + (f" extends {ext}" if ext else "")
                        + (
                            " { // class component: %d nodes" % mainR["thr"]
                            if debug
                            else " {"
                        )
                        + "\n"
                    )

                # Files that declare more than one class (a leading anonymous
                # or nested class encoded before/among the main class) repeat
                # method names across component groups. Merging them into one
                # class is a compile error, so split at the first repeated
                # name and name the groups from the tail class records.
                fnNames = [fn_name_of(sm[0]) for sm in subMeta]
                # closures repeat routinely inside ONE class; only real
                # method names mark a second class group
                fnNames = [f for f in fnNames if f and not f.endswith("{closure}")]
                multi = len(fnNames) != len(set(fnNames))
                allLeafs: list[str] = []
                seenLeaf = {cls}
                for nm in class_like_names(stream, tailStart):
                    lf = nm.split("@")[0].rsplit("\\", 1)[-1]
                    if (
                        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", lf)
                        and lf not in seenLeaf
                    ):
                        seenLeaf.add(lf)
                        allLeafs.append(lf)
                tailLeafs = allLeafs if multi else []
                firstAlt = tailLeafs[0] if (multi and tailLeafs) else None
                if firstAlt is not None and firstAlt != cls:
                    # the first component group is the leading class; keep the
                    # main class (and remaining names) for later groups
                    prodQueue = [(cls, parent)] + [(lf, None) for lf in tailLeafs[1:]]
                    _open_class(firstAlt)
                else:
                    prodQueue = [(lf, None) for lf in tailLeafs]
                    _open_class(cls, parent)
                prodClassOpen = True
                prodQueueNames = [cls] + allLeafs

    # ---- eval class/enum recovery ----
    evalEnum: dict | None = None
    from .classrec import class_tail, enum_cases, prop_declare, promoted_param

    if not isProd:
        subsEnd = max((m[3] + len(m[2]) for m in subMeta), default=boff + bsize)
        cases = enum_cases(stream, boff + bsize, subsEnd)
        ct = class_tail(stream, subsEnd, len(stream))
        if cases:
            evalEnum = {"cases": cases, "tail": ct}
            out.append(f"\nenum {subMeta[0][1][0]}: string {{\n")
            for cn, cv in cases:
                if cv is None:
                    out.append(f"    case {cn};\n")
                elif isinstance(cv, str):
                    out.append(f"    case {cn} = '{cv}';\n")
                else:
                    out.append(f"    case {cn} = {cv};\n")
            out.append("}\n")
        elif ct:
            evalEnum = {"cases": [], "tail": ct}
        # constructor promotion: promoted property records map onto the
        # ctor's parameter list in declaration order, starting at param 0
        if evalEnum and evalEnum.get("tail"):
            prom = [p for p in evalEnum["tail"]["props"] if p["vis"] & 0x80]
            if prom:
                evalEnum["promoted"] = prom

    # ---- eval main class skeleton ----
    # The eval class guess below reads descriptor records and on this encoder
    # generation often names the *parent* (or nothing) as the class, yielding
    # methods outside any class or `class Modules extends Modules`. Prefer the
    # main component's DECLARE_CLASS operands; fall back to the class record
    # the encoder writes after the main wire (its leaf matches the filename).
    evalMainOpen = False
    evalMainDesc: str | None = None
    openClass = None
    if not isProd and not (evalEnum and evalEnum["cases"]):
        mainDecl = _declared_class(mainMeta.get("resolved") or mainR)
        leaf = os.path.basename(path)
        if leaf.endswith(".php"):
            leaf = leaf[:-4]
        if leaf.endswith(".class"):
            leaf = leaf[:-6]
        mainCls = class_name_hint(stream, boff + bsize, leaf)
        if mainCls is None:
            # fall back to the first tail class record when the filename
            # identifies it: the `*.class.php` convention, or the record's
            # leaf being a suffix of the stem (This is in some legacy code
            # ported from Zend).
            names = class_like_names(
                stream, boff + bsize,
                subMeta[0][3] if subMeta else len(stream),
            )
            if names:
                cand = names[0]
                cand_leaf = cand.rsplit("\\", 1)[-1]
                if os.path.basename(path).endswith(".class.php") or (
                    cand_leaf and leaf.lower().endswith(cand_leaf.lower())
                ):
                    mainCls = cand
        mainParent = mainDecl[1] if mainDecl else None
        if mainCls is None and mainDecl:
            mainCls = mainDecl[0]
        if mainCls is not None and mainDecl is None and mainR["thr"] <= 1:
            # a trivial main component whose filename hint matches a
            # sub-function leaf is a function file, not a class: emit its
            # namespace and keep the function top-level (json_decode.php)
            leaf_l = mainCls.rsplit("\\", 1)[-1].lower()
            match_fn = None
            for _sm in subMeta:
                sfn = fn_name_of(_sm[0])
                if sfn and sfn.rsplit("\\", 1)[-1].lower() == leaf_l:
                    match_fn = sfn
                    break
            if match_fn is not None:
                ns = match_fn.rsplit("\\", 1)[0] if "\\" in match_fn else None
                if ns:
                    out.append(f"\nnamespace {ns};\n")
                mainCls = None
        if mainCls is not None:
            ns = None
            clsLeaf = mainCls
            if "\\" in clsLeaf:
                ns, clsLeaf = clsLeaf.rsplit("\\", 1)
            if mainParent is not None:
                if mainParent.lower().lstrip("\\") == mainCls.lower().lstrip("\\"):
                    mainParent = None
                else:
                    mainParent = "\\" + mainParent.lstrip("\\")
            if ns:
                out.append(f"\nnamespace {ns};\n")
            doc = tail_doccomment(stream, boff + bsize)
            if doc is not None:
                out.append("\n" + doc + "\n")
            out.append(
                f"\nclass {clsLeaf}"
                + (f" extends {mainParent}" if mainParent else "")
                + " {\n"
            )
            if evalEnum and evalEnum.get("tail"):
                from .classrec import prop_declare

                for p in evalEnum["tail"]["props"]:
                    if p["vis"] & 0x80:
                        # promoted onto the ctor parameter list
                        continue
                    out.append(prop_declare(p) + "\n")
                for nm, cv in evalEnum["tail"]["consts"]:
                    lit = (
                        f"'{cv}'"
                        if isinstance(cv, str)
                        else ("null" if cv is None else repr(cv))
                    )
                    out.append(f"    const {nm} = {lit};\n")
            openClass = clsLeaf
            evalMainOpen = True

    # ---- sub-function components ----
    # per-sub class tables (property/const records the encoder wrote into
    # each sub's descriptor region) — indexed by sub order
    subTails: dict[int, dict] = {}
    for _si in range(len(subMeta)):
        _o = subMeta[_si][3]
        _start = subMeta[_si - 1][3] + len(subMeta[_si - 1][2]) if _si else boff + bsize
        _pt = class_tail(stream, _start, _o - 4)
        if _pt and _pt["props"]:
            subTails[_si] = _pt
    for si, sm in enumerate(subMeta):
        r, rec, wirebytes, off, recSeeds = sm
        fn = fn_name_of(r)
        meta = {
            "isFn": True,
            "fnName": fn,
            "recSeeds": recSeeds,
            "closure_at": nextOuterClosure,
        }
        meta["cv"] = cv_names(r, "prod" if isProd else "eval", rec)
        if not isProd:
            for k, an in enumerate(arg_names(r)):  # authoritative arg names
                if an:
                    meta["cv"][k] = an
        classRec = None
        parentRec = None
        # the class-record layout: a leading run of capitalized names is the
        # ancestor chain (class, parent, interfaces) — the declared class is
        # the first capitalized name AFTER that run (gdiverse4: ['Suit',
        # 'UnitEnum', 'BackedEnum', 'name', 'value', 'Card', ...] -> Card,
        # not Suit); a rec of only the ancestor chain (prod: TaxGateway,
        # NE_Model) keeps rec[0]. Lowercase method/prop names in between
        # end the run. fn names never participate.
        capsRun = 0
        for s in rec:
            if s[:1].isupper() and s.lower() != s:
                capsRun += 1
            else:
                break
        for s in rec[capsRun:]:
            if s == fn:
                continue
            if (
                s[:1].isupper()
                and s.lower() != s
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\]*", s)
            ):
                classRec = s
                break
        if classRec is None and capsRun:
            # a rec of just the current method name (`['SSL']`,
            # `['Fail2ban']`) is not a class record; treating it as one
            # opens bogus class groups inside the already-open main class
            if rec and rec[0] != fn:
                classRec = rec[0]
                if capsRun > 1 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\]*", rec[1]):
                    parentRec = rec[1]
        # the declared class was found after the ancestor run: the next
        # capitalized non-fn string after it is still the parent
        # (gt_diverse3 ctor: ['name', 'Dog', 'Animal', ...] -> extends Animal)
        if classRec is not None and parentRec is None:
            ki = rec.index(classRec)
            for s in rec[ki + 1 :]:
                if s == fn:
                    continue
                if (
                    s[:1].isupper()
                    and s.lower() != s
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\]*", s)
                ):
                    parentRec = s
                    break
        # eval descriptor records in method components are method/parameter/
        # local names, not additional class declarations: the main class
        # skeleton (when there is one) is authoritative, and function-file
        # components stay top-level.  Production keeps its class-group logic.
        if not isProd and (evalMainOpen or disableRecClasses or not classFile):
            classRec = None
            parentRec = None
        if not isProd and not prodClassOpen:
            if evalMainOpen and classRec is not None:
                # the first descriptor-named class group is the main class
                # (on this encoder generation its record names the parent)
                if evalMainDesc is None:
                    evalMainDesc = classRec
                if classRec == evalMainDesc:
                    classRec = None
            if classRec is not None and (
                openClass is None or classRec.lower() != openClass.lower()
            ):
                # extending yourself is not allowed; the descriptor's
                # class/parent pair can hold the same name here
                if (
                    parentRec is not None
                    and parentRec.lower().lstrip("\\") == classRec.lower().lstrip("\\")
                ):
                    parentRec = None
                if openClass is not None:
                    # the class table the encoder wrote into THIS sub's
                    # descriptor region belongs to the class being closed
                    # (gt_diverse3: Animal's `name` sits before the Dog
                    # record in the Dog-ctor region)
                    pt = subTails.get(si)
                    if pt:
                        from .classrec import prop_declare

                        for p in pt["props"]:
                            if p["vis"] & 0x80:
                                continue
                            out.append(prop_declare(p) + "\n")
                        for nm, cv in pt["consts"]:
                            lit = (
                                f"'{cv}'"
                                if isinstance(cv, str)
                                else ("null" if cv is None else repr(cv))
                            )
                            out.append(f"    const {nm} = {lit};\n")
                    out.append("}\n\n")
                out.append(
                    f"\nclass {classRec}"
                    + (f" extends {parentRec}" if parentRec else "")
                    + " {\n"
                )
                if evalEnum and evalEnum.get("tail"):
                    from .classrec import prop_declare

                    for p in evalEnum["tail"]["props"]:
                        if p["vis"] & 0x80:
                            # promoted onto the ctor parameter list
                            continue
                        out.append(prop_declare(p) + "\n")
                    for nm, cv in evalEnum["tail"]["consts"]:
                        lit = (
                            f"'{cv}'"
                            if isinstance(cv, str)
                            else ("null" if cv is None else repr(cv))
                        )
                        out.append(f"    const {nm} = {lit};\n")
                openClass = classRec
            elif classRec is None and openClass is None:
                out.append("\n")
        label = f"function {classRec + '::' if classRec else ''}" + (
            fn if fn is not None else f"@{off:#x}"
        )
        # multi-class production files: a repeated method name marks a new
        # class group (anonymous/nested classes are encoded interleaved)
        if prodClassOpen and fn is not None and not fn.endswith("{closure}"):
            if fn in prodSeen:
                out.append("}\n")
                if prodQueue:
                    nxt, nxtExt = prodQueue.pop(0)
                else:
                    prodSerial += 1
                    nxt, nxtExt = f"{cls}_{prodSerial}", None
                _open_class(nxt, nxtExt)
                prodSeen = set()
            prodSeen.add(fn)
        if prodClassOpen:
            meta["classNames"] = [cls] + prodQueueNames
        meta["classDepth"] = bool(openClass is not None or prodClassOpen)
        if not isProd and evalEnum and evalEnum.get("promoted") and fn == "__construct":
            from .classrec import promoted_param

            meta["promote"] = {
                k: promoted_param(p) for k, p in enumerate(evalEnum["promoted"])
            }
            meta["promotedProps"] = {p["name"] for p in evalEnum["promoted"]}
        if fn.endswith("{closure}"):
            # a bare anonymous-function component: emitting `function () {}`
            # anywhere (top level OR a class body) is invalid PHP; its body
            # is inlined at the declaring component's DECLARE_LAMBDA site
            # (pre-render pass)
            continue
        liftOne(wirebytes, r, meta, label)
    if openClass is not None:
        out.append("}\n")
    if prodClassOpen:
        out.append("} // end class\n" if debug else "}\n")
    # a file-level `namespace` must precede every other statement; the main
    # component's top-level code (define/require_once) is emitted first, so
    # move a late namespace up to just after `<?php`
    for ix in range(2, len(out)):
        if out[ix].lstrip().startswith("namespace "):
            out.insert(1, out.pop(ix))
            break
    return {"text": "".join(out), "gt": gt_report, "stderr": stderr}


__all__ = ["PipelineError", "lift_file"]
