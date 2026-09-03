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
from .wires import classrec_strings, desc_strings, pool_strings, record_seeds, scan_wires, tail_doccomment
from .emitter import walk_component
from .model import LiftContext

_IDENT = re.compile(r"^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$")


class PipelineError(Exception):
    pass


def lift_file(path: str, chunk: int = 1, arena=None, ktab=None, gt=None,
              auto: bool = True, m5dir: str | None = None,
              valid_php: bool = False) -> dict:
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
        subMeta.append((r, rec, off, size, record_seeds(stream, prevEnd, off - 4, size)))
        prevEnd = off + size

    # opcode capture pool: m5 auto-discovery + explicit --arena/--ktab
    captureDirs: list[str] = []
    if auto and not isProd:
        d = m5_sample_dir(mainWire, m5dir or os.environ.get("IONCUBE_RE_M5_DIR", ""))
        if d is not None:
            captureDirs.append(d)
            stderr.append("ic_lift: m5 capture match: %s (arena/ktab reuse)" % os.path.basename(d))
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
    out.append(f"// ic_lift: {os.path.basename(path)} — mode: {mode} — "
               f"{1 + len(subMeta)} component(s)\n")
    if isProd:
        out.append("// production chain (ICB0->chunk->container->frame codec->deflate->component->layer-B) verified offline\n")

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
                r = der[0]
                meta["opSrc"] = der[1]
        meta.setdefault("opSrc", "wire-only")
        ctx = LiftContext.build(wire, r, meta)
        ctx.valid_php = valid_php
        out.append(f"// ===== component: {label} — thr={r['thr']} nodes, "
                   f"opcodes: {meta['opSrc']} =====\n")
        if meta.get("isFn"):
            cd = 1 if meta.get("classDepth") else 0
            fn = ctx.fnName if ctx.fnName is not None else "{fn}"
            specs, ret = arg_specs(r)
            sig = ", ".join(param_list(ctx))
            retPart = f": {ret}" if ret else ""
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
            line = ("  gt %-24s opcode match %d/%d gt oplines (+%d rule-expanded nodes, thr=%d)%s"
                    % (sec, ok, len(gtsecs[sec]), extra, tot, " MISSES:" if miss else ""))
            gt_report.append(line)
            for m in miss:
                gt_report.append("      " + m)
            gtIdx += 1

    # ---- main component ----
    mainMeta = {"isFn": False}
    if mainR["fnrec"] is not None:
        mainMeta["fnName"] = fn_name_of(mainR)
    mainMeta["cv"] = {} if isProd else (mainDesc or cv_names(mainR, "eval", []))
    liftOne(mainWire, mainR, mainMeta,
            f"function {fn_name_of(mainR)}" if mainR["fnrec"] is not None else "main")

    # ---- production class skeleton ----
    prodClassOpen = False
    if isProd:
        tailStart = boff + bsize
        if len(stream) > tailStart + 5 and stream[tailStart : tailStart + 2] == b"\x00\x00" \
                and stream[tailStart + 4] == 2:
            rec = classrec_strings(stream, tailStart, tailStart + 0x60)
            ps = [s.decode("latin-1") for s in pool_strings(mainR["pool"])]
            cls = rec[0] if rec else (ps[1] if len(ps) > 1 else "?")
            parent = None
            if len(rec) > 1 and rec[1] != cls and re.search("[A-Z]", rec[1]):
                parent = rec[1]
            elif len(ps) > 0 and ps[0] != cls:
                parent = ps[0]
            doc = tail_doccomment(stream, tailStart)
            if doc is not None:
                out.append("\n" + doc + "\n")
            out.append(f"\nclass {cls}" + (f" extends {parent}" if parent else "")
                       + f" {{ // class component: {mainR['thr']} nodes\n")
            prodClassOpen = True

    # ---- sub-function components ----
    openClass = None
    for sm in subMeta:
        r, rec, off, size, recSeeds = sm
        fn = fn_name_of(r)
        meta = {"isFn": True, "fnName": fn, "recSeeds": recSeeds}
        meta["cv"] = cv_names(r, "prod" if isProd else "eval", rec)
        if not isProd:
            for k, an in enumerate(arg_names(r)):  # authoritative arg names
                if an:
                    meta["cv"][k] = an
        classRec = None
        parentRec = None
        for s in rec:
            if s == fn:
                continue
            if s[:1].isupper():
                if classRec is None:
                    classRec = s
                elif s != classRec and parentRec is None:
                    parentRec = s
        if not isProd and not prodClassOpen:
            if classRec is not None and classRec != openClass:
                if openClass is not None:
                    out.append("}\n\n")
                out.append(f"\nclass {classRec}" + (f" extends {parentRec}" if parentRec else "") + " {\n")
                openClass = classRec
            elif classRec is None and openClass is None:
                out.append("\n")
        label = f"function {classRec + '::' if classRec else ''}" \
            + (fn if fn is not None else f"@{off:#x}")
        meta["classDepth"] = bool(openClass is not None or prodClassOpen)
        liftOne(stream[off : off + size], r, meta, label)
    if openClass is not None:
        out.append("}\n")
    if prodClassOpen:
        out.append("} // end class\n")
    return {"text": "".join(out), "gt": gt_report, "stderr": stderr}


__all__ = ["PipelineError", "lift_file"]
