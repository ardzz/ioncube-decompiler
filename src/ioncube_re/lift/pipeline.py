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
) -> dict:
    """Lift one encoded file. Returns {'text': str, 'gt': [lines], 'stderr': [lines]}.

    Raises PipelineError on decode/parse failure (the PHP tool exits 2 there)."""
    stderr: list[str] = []
    with open(path, "rb") as f:
        data = f.read()
    isProd = data[:12] == b"<?php //ICB0"

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
        subMeta.append(
            (
                r,
                rec,
                stream[off : off + size],
                off,
                record_seeds(stream, prevEnd, off - 4, size),
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
            subMeta.append(
                (
                    r,
                    rec,
                    mainWire[off : off + size],
                    off,
                    record_seeds(mainWire, prevN, off - 4, size),
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
                "ic_lift: m5 capture match: %s (arena/ktab reuse)" % os.path.basename(d)
            )
    pairPool = capture_pairs(captureDirs)
    if arena and ktab:
        pairPool.insert(0, (arena, ktab))

    # offline keytable inputs (M6-KEYTAB): ierg + X from the main blob
    offlineIerg = None
    offlineX = 6 if isProd else 2
    if isProd:
        _fields, chunks = prod_chunks(path)
        cont = prod_container(chunks[chunk - 1], "lift")
        mb = layer_a(cont["blob"], cont["seed"])
        # mainblob: [ver@0][f@4][f@8][A@0xc][str_len@0x10][str bytes][IERG][namekey]
        # [X if v>5] — ierg/X sit at 0x14/0x1c + str_len (eval/CE str_len=0;
        # the Blesta generation carries a 16-byte string -> +0x10). M6-SUBWIRE §7.1.
        sl = u32(mb, 0x10)
        offlineIerg = u32(mb, 0x14 + sl)
        offlineX = u32(mb, 0x1C + sl)
        if offlineX > 64:
            offlineX = 6  # implausible X (8.1-target chunks) -> CE default
    else:
        dr = decrypt_file(path)  # validates adler+MD4
        sl = u32(dr["plain"], 0x10)
        offlineIerg = u32(dr["plain"], 0x14 + sl)
        offlineX = u32(dr["plain"], 0x1C + sl)
        if offlineX > 64:
            offlineX = 2  # implausible X -> the eval default
    mainSeeds = (u32(stream, 0x08), u32(stream, 0x0C))

    out: list[str] = ["<?php\n"]
    if debug:
        out.append(
            f"// ic_lift: {os.path.basename(path)} — mode: {mode} — "
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
                out.append("    " * cd + f"function {fn}({sig}){retPart} {{\n")
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
                seeds = record_seeds(mainWire, prevN, off - 4, size)
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

    liftOne(
        mainWire,
        mainR,
        mainMeta,
        f"function {fn_name_of(mainR)}" if mainR["fnrec"] is not None else "main",
    )

    # ---- production class skeleton ----
    prodClassOpen = False
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
                out.append(
                    f"\nclass {cls}"
                    + (f" extends {parent}" if parent else "")
                    + (
                        " { // class component: %d nodes" % mainR["thr"]
                        if debug
                        else " {"
                    )
                    + "\n"
                )
                prodClassOpen = True

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

    # ---- sub-function components ----
    openClass = None
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
        meta = {"isFn": True, "fnName": fn, "recSeeds": recSeeds}
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
        # when the class is found after the ancestor run, the run holds a
        # SIBLING class record (gdiverse4: the enum Suit block precedes
        # Card) — no parent is recoverable from it
        if not isProd and not prodClassOpen:
            if classRec is not None and classRec != openClass:
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
    return {"text": "".join(out), "gt": gt_report, "stderr": stderr}


__all__ = ["PipelineError", "lift_file"]
