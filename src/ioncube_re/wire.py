"""Component WIRE format parser + node assembler (ic_wire port, M6-OPERANDS).

Grammar (FUN_002086c8): [0x7c] op-array header (31 u32s) -> checksum u32 ->
opa+0x40 u32 -> [16] fn-name record if hdr+0x08 -> [16] doc record if
hdr+0x68 -> const-hash count -> [tc*16] try/catch records -> pre-node
records (arg_info-ish: FUN_00206e3f pairs + a 0x10712e zval, with class-name
sub-records when ctrl&0x1000000 / list when ctrl&0x400000) -> fn-info count
-> keytable count -> OP-ARRAY u32 count + records -> ENTRY count + 5-byte
entries -> [lc*16] literals -> [lr*16] live ranges -> opa+0x38 u32 -> pool
("c0de" magic + NUL-terminated, even-padded strings) -> zval records ->
sub-function components.

The op-array grammar is VERSION-GATED: v>5 wires carry [op][sig] per node
(eval 8.1, CE 8.4 chunks), v<=5 wires carry [op] only (CE 8.2/8.3 chunks,
mask loses its K2 leg). Mode = auto-detected by exact u32/entry consumption
(unique on 62/62 wires).

Node assembly (FUN_002075ca): final = raw ^ K1 (^ K2 in sig mode);
K1 = ktab[i], K2 = ktab[thr+X+i]; operands per the §1.3 conversions.
"""

import re
import struct
import sys

from .container import i32, u16, u32
from .crypto.keytable import kt_generate
from .crypto.layerb import EVAL_KEY, component_decrypt
from .interned import interned_name
from .opcodes import HANDLER2OP, OPNAMES


class WireError(Exception):
    pass


class WireReader:
    __slots__ = ("b", "p")

    def __init__(self, b: bytes, p: int = 0):
        self.b = b
        self.p = p

    def _need(self, n: int):
        if self.p + n > len(self.b):
            raise WireError(
                f"wire truncated: need {n} bytes at offset {self.p} of {len(self.b)}"
            )

    def u32(self) -> int:
        self._need(4)
        v = u32(self.b, self.p)
        self.p += 4
        return v

    def i32(self) -> int:
        self._need(4)
        v = i32(self.b, self.p)
        self.p += 4
        return v

    def raw(self, n: int) -> bytes:
        self._need(n)
        v = self.b[self.p : self.p + n]
        self.p += n
        return v

    def x06e3f(self) -> tuple[int, int] | None:
        """FUN_00206e3f: [ctrl][param] -> obj | NULL (ctrl<0 or param bit31)."""
        c = self.i32()
        if c < 0:
            return None
        p = self.u32()
        if p >= 0x80000000:
            return None
        return (c, p)


HDRF = {
    0x00: "type|arg_flags", 0x04: "fn_flags", 0x08: "fn_name_ptr", 0x0C: "scope_ptr",
    0x10: "prototype_ptr", 0x14: "num_args", 0x18: "num_required", 0x1C: "arg_info/nodes_ptr",
    0x20: "static_vars", 0x24: "T*8 (last_opline-ish)", 0x28: "literal_count",
    0x2C: "->opa+0x40", 0x30: "THR (node count)", 0x34: "->opa+0x48",
    0x44: "->opa+0x68", 0x48: "->opa+0x70", 0x4C: "live_range_count",
    0x50: "try_catch_count", 0x54: "ptr", 0x58: "->opa+0x88",
    0x60: "->opa+0x98", 0x64: "->opa+0x9c", 0x68: "doc_comment?",
    0x6C: "ZVAL_RECORD_COUNT", 0x70: "SUB_FUNCTION_COUNT", 0x74: "->opa+0xb0",
    0x78: "->opa+0xb8",
}

_SEND_OPS = (0x32, 0x41, 0x42, 0x43, 0x6A, 0x74, 0x75, 0x77, 0x78, 0xA5, 0xB9)
_JMPZ_OPS = (0x2B, 0x2C, 0x2E, 0x2F, 0x4D, 0x7D, 0x97, 0x98, 0xA9, 0xC6)


def parse_wire(w: bytes, kt: bytes | None = None, arena: bytes | None = None,
               xoff: int = 2) -> dict:
    """Parse + assemble one wire blob. kt enables the opcode demask; arena
    (live capture) additionally resolves wD0 nodes via the demasked handler."""
    r = WireReader(w)
    hdr = r.raw(0x7C)
    s1 = 0
    s2 = 0
    for c in hdr:
        s1 = (s1 + c) & 0xFF
        s2 = (s2 + s1) & 0xFF
    chk = u16(w, 0x7C)
    chkok = chk == ((s1 | (s2 << 8)) & 0xFFFF)
    r.raw(4)  # checksum u32 (low 16 checked)
    r.u32()  # local_140 -> opa+0x40
    fn = u32(hdr, 4)
    if u32(hdr, 0x68) != 0:
        r.raw(16)  # doc-comment record
    fnrec = None
    if i32(hdr, 8) != 0:
        fnrec = r.raw(16)  # function-name record
    htc = r.i32()
    if htc > 0:
        print(f"note: const-hash entries present ({htc}) — reader not modeled", file=sys.stderr)
    tc = u32(hdr, 0x50)
    r.raw(tc << 4)
    thr = u32(hdr, 0x30)
    # pre-node records (arg_info-ish)
    npre = u32(hdr, 0x14) + (1 if fn & 0x2000 else 0) + (1 if fn & 0x4000 else 0)
    pre = []
    for _ in range(npre):
        a = r.x06e3f()
        b = r.x06e3f()
        zc = r.u32()
        zrec = None
        names = None
        if zc & 0x1000000:
            zrec = r.x06e3f()
        elif zc & 0x400000:
            n = r.u32()
            names = []
            for k in range(max(n - 1, 0)):
                c2 = r.u32()
                if c2 & 0x1000000:
                    r.x06e3f()
        pre.append({"a": a, "b": b, "ctrl": zc, "zrec": zrec, "names": names})
    fi = r.i32()
    if fi > 0:
        print(f"note: fn-info entries present ({fi}) — reader not modeled", file=sys.stderr)
    ktcnt = r.i32()
    opcnt = r.i32()
    ops = [r.u32() for _ in range(opcnt)]
    entcnt = r.i32()
    entries = r.raw(entcnt * 5)
    lc = u32(hdr, 0x28)
    lits = r.raw(lc << 4)
    lr = u32(hdr, 0x4C)
    live = r.raw(lr << 4)
    r.u32()  # -> opa+0x38
    poolsz = r.u32()
    pool = r.raw(poolsz)
    # zval records
    zv = []
    for _ in range(u32(hdr, 0x6C)):
        a = r.u32()
        b = r.u32()
        ty = r.u32()
        ex = r.u32()
        e = {"a": a, "b": b, "type": ty, "extra": ex}
        if (ty & 0xFF) in (6, 7, 0xB):
            off = r.u32()
            ln = r.u32()
            e["off"] = off
            e["len"] = ln
            if ln > 0 and (off & 0x10000000) == 0 and off < poolsz:
                e["str"] = pool[off : off + ln]
        zv.append(e)
    sf = u32(hdr, 0x70)

    # ---- grammar mode auto-detection (exact u32/entry consumption) ----
    mode = "sig"
    modeok = False
    for trymode in ("sig", "nosig"):
        jj = 0
        ents = 0
        okmode = True
        for i in range(thr):
            need = 2 if trymode == "sig" else 1
            if jj + need > opcnt:
                okmode = False
                break
            op = ops[jj]
            jj += need
            if (op & 0x1800) == 0x1800:
                if jj >= opcnt:
                    okmode = False
                    break
                jj += 1
            if (op >> 16) == 0xFFFF:
                if jj >= opcnt:
                    okmode = False
                    break
                jj += 1
            ents += ((op & 0x100) and 1) + ((op & 0x200) and 1) + ((op & 0x400) and 1)
        if okmode and jj == opcnt and ents == entcnt:
            mode = trymode
            modeok = True
            break
    if not modeok:
        print(
            f"ic_wire: WARNING: neither grammar fits thr={thr} opcnt={opcnt} entcnt={entcnt}; "
            "node decode is UNRELIABLE",
            file=sys.stderr,
        )

    # ---- node assembly ----
    nodes = []
    j = 0
    ep = 0
    zvc = len(zv)

    def cv(t: int, v: int) -> int:
        if t & 8:
            return (v + 5) * 0x10
        if t & 6:
            return (lc + v + 5) * 0x10
        return v

    for i in range(thr):
        if j >= opcnt:
            break  # no-fit guard
        op = ops[j]
        if mode == "sig":
            sig = ops[j + 1]
            j += 2
        else:
            sig = None
            j += 1
        rawop = op & 0xFF
        extenc = op & 0x1800
        ext = 0
        if extenc == 0x800:
            ext = 1
        elif extenc == 0x1000:
            ext = 0x3C
        elif extenc == 0x1800:
            ext = ops[j]
            j += 1
        lineno = op >> 16
        if lineno == 0xFFFF:
            lineno = ops[j]
            j += 1
        ent: dict[str, tuple[int, int]] = {}
        for nm, bit in (("res", 0x100), ("op1", 0x200), ("op2", 0x400)):
            if op & bit:
                ent[nm] = (entries[ep], u32(entries, ep + 1))
                ep += 5
        k1 = kt[i] if kt is not None and i < len(kt) else None
        k2 = kt[thr + xoff + i] if kt is not None and thr + xoff + i < len(kt) else None
        if mode == "sig":
            final = (rawop ^ k1 ^ k2) if (k1 is not None and k2 is not None) else None
        else:
            final = (rawop ^ k1) if k1 is not None else None
        # arena mode: the TRUE opcode from the demasked handler
        trueop = None
        if arena is not None and k1 is not None:
            lo = u32(arena, i * 0x20)
            mlo = (k1 * 0x01010101) & 0xFFFFFFFF
            hva = (lo ^ mlo) & 0xFFFFF
            nm2 = HANDLER2OP.get(hva)
            if nm2 is not None:
                for num, name in OPNAMES.items():
                    if name == nm2:
                        trueop = num
                        break
        # sig validation (sig mode only; keys at ktab[thr+3i..+3])
        sigok = None
        if mode == "sig" and sig is not None and kt is not None and thr + 3 * i + 3 <= len(kt):
            k0 = kt[thr + 3 * i]
            k1s = kt[thr + 3 * i + 1]
            k2s = kt[thr + 3 * i + 2]
            der = k0 | (k1s << 8) | (k2s << 16) | ((k0 ^ k1s) << 24)
            sigok = sig == ((~der) & 0xFFFFFFFF)
        t1 = ent.get("op1", (0, 0))[0]
        t2 = ent.get("op2", (0, 0))[0]
        rt = ent.get("res", (0, 0))[0]
        op1 = cv(t1, ent["op1"][1]) if "op1" in ent else 0
        op2 = cv(t2, ent["op2"][1]) if "op2" in ent else 0
        res = cv(rt, ent["res"][1]) if "res" in ent else 0
        if t1 == 1 and "op1" in ent and ent["op1"][1] < zvc:
            op1 = ent["op1"][1] * 0x10 + (thr - i) * 0x20
        if t2 == 1 and "op2" in ent and ent["op2"][1] < zvc:
            op2 = ent["op2"][1] * 0x10 + (thr - i) * 0x20
        f = trueop if trueop is not None else final
        if f is not None:
            if f in _SEND_OPS and t2 != 1:
                res = (op2 + 4) * 0x10
            if f == 0x2A and "op1" in ent:
                op1 = (ent["op1"][1] + 1) * 0x20 - i * 0x20
            if f in _JMPZ_OPS and "op2" in ent:
                op2 = (ent["op2"][1] + 1) * 0x20 - i * 0x20
        nodes.append({
            "i": i, "op": op, "raw": rawop, "sig": sig, "sigok": sigok,
            "final": final, "trueop": trueop, "ext": ext, "lineno": lineno,
            "ent": ent, "t1": t1, "t2": t2, "rt": rt,
            "op1": op1, "op2": op2, "res": res,
        })
    return {
        "hdr": hdr, "chk": chkok, "thr": thr, "fn": fn, "fnrec": fnrec,
        "ktcnt": ktcnt, "opcnt": opcnt, "entcnt": entcnt, "ops": ops,
        "nodes": nodes, "pool": pool, "zvals": zv, "lits": lits, "live": live,
        "sf": sf, "mode": mode, "pre": pre,
        "end": r.p, "len": len(w),
    }


# ---------------- rendering (byte-exact with the PHP oracle) ----------------


_ADDCSLASH_SPECIAL = {0x09: "\\t", 0x0A: "\\n", 0x0B: "\\v", 0x0C: "\\f", 0x0D: "\\r"}


def _php_addcslashes(s: bytes) -> str:
    """PHP addcslashes($s, "\\0..\\x1f"): \\t\\n\\v\\f\\r special forms,
    other control bytes -> 3-digit octal, everything else passes through."""
    out = []
    for b in s:
        if b < 0x20:
            out.append(_ADDCSLASH_SPECIAL.get(b) or f"\\{b:03o}")
        else:
            out.append(chr(b))
    return "".join(out)


def fmt_node(n: dict, zvals: list[dict]) -> str:
    f0 = n["trueop"] if n["trueop"] is not None else n["final"]
    if f0 is not None and f0 in OPNAMES:
        opn = OPNAMES[f0]
    elif f0 is not None:
        opn = f"op{f0}"
    else:
        opn = "op?"

    def zref(t: int, v: int) -> str | None:
        if t != 1 or v >= len(zvals):
            return None
        z = zvals[v]
        zt = z["type"] & 0xFF
        if zt == 4:
            return f"int({z['a']})"
        if zt == 1:
            return "null"
        if zt == 6 and "str" in z:
            return 'string("%s")' % z["str"].decode("latin-1")
        if zt == 0x12:
            return f"bool({z['a']})"
        if zt == 7:
            return f"array[{z.get('len', 0)}B]"
        return "zval"

    flds = []
    for nm, d in (("op1", (n["t1"], n["op1"], n["ent"]["op1"][1] if "op1" in n["ent"] else None)),
                  ("op2", (n["t2"], n["op2"], n["ent"]["op2"][1] if "op2" in n["ent"] else None))):
        if nm not in n["ent"]:
            continue
        z = zref(d[0], d[2])
        if z is not None:
            flds.append(f"{nm}={z}")
        elif d[0] == 8:
            flds.append(f"{nm}=CV({int(d[1] / 0x10) - 5})")
        elif d[0] & 6:
            flds.append(f"{nm}={'V' if d[0] & 4 else 'T'}{int(d[1] / 0x10 - 5)}")
        else:
            flds.append(f"{nm}={d[2]}")
    if "res" in n["ent"] and n["rt"] & 0xE:
        if n["rt"] == 8:
            flds.append(f"res=CV({int(n['res'] / 0x10) - 5})")
        elif n["rt"] & 6:
            flds.append(f"res={'V' if n['rt'] & 4 else 'T'}{int(n['res'] / 0x10 - 5)}")
    return "%04d %s %s lin=%d" % (n["i"], opn, " ".join(flds), n["lineno"])


def render_wire_report(r: dict, basename: str) -> list[str]:
    """The == header, pool, zvals, and node lines — identical to the PHP CLI's."""
    out = []
    out.append(
        "== %s: %dB thr=%d fn=%08x chk=%s walk=%d/%d mode=%s ktcnt=%d opcnt=%d "
        "entcnt=%d pool=%dB zv=%d sf=%d"
        % (basename, r["len"], r["thr"], r["fn"], "OK" if r["chk"] else "BAD",
           r["end"], r["len"], r["mode"], r["ktcnt"], r["opcnt"], r["entcnt"],
           len(r["pool"]), len(r["zvals"]), r["sf"])
    )
    for o, nm in HDRF.items():
        out.append("   +%-3x %-24s %08x" % (o, nm, u32(r["hdr"], o)))
    out.append("   pool: %s" % _php_addcslashes(r["pool"])[:100])
    for i, z in enumerate(r["zvals"]):
        line = "   zval%-2d type=%03x a=%08x b=%08x" % (i, z["type"], z["a"], z["b"])
        if "len" in z:
            line += " off=%d len=%d%s" % (
                z["off"], z["len"], " " + _php_addcslashes(z["str"]) if "str" in z else ""
            )
        out.append(line)
    sigokn = 0
    sign = 0
    for n in r["nodes"]:
        if n["sigok"] is not None:
            sign += 1
            if n["sigok"]:
                sigokn += 1
        out.append("   " + fmt_node(n, r["zvals"]))
    if sign:
        out.append("   sig: %d/%d valid (rest = wD0 anti-tamper path)" % (sigokn, sign))
    if r["end"] != r["len"]:
        out.append("   WALK OVER/UNDERFLOW: %d != %d" % (r["end"], r["len"]))
    return out


# ---------------- stream descriptor (M6-OPERANDS §1.3) ----------------


def parse_stream_desc(s: bytes) -> dict | None:
    """Conventional vs var-embedded component-stream descriptor; locates the
    blob by the 1ea1e5ae signature."""
    n = len(s)
    size = u32(s, 4)
    pos = None
    for p in range(0x4C, min(n, 0x4C + 0x400) - 3):
        if s[p : p + 4] == b"\x1e\xa1\xe5\xae":
            pos = p
            break
    if pos is None:
        return None
    strings = []
    if pos != 0x4C:
        p = 0x43
        while p + 4 <= pos:
            ln = u16(s, p)
            if ln > 0 and s[p + 2] == 0x00 and s[p + 3] == 0x20 and p + 4 + ln <= pos:
                strings.append(s[p + 4 : p + 4 + ln])
                p += 4 + ln
            else:
                break
    pred = 0x43 + sum(len(x) for x in strings) + 4 * len(strings) + 9 if strings else 0x4C
    return {
        "size": size, "seedA": u32(s, 8), "seedB": u32(s, 0xC), "f10": u32(s, 0x10),
        "f48": u32(s, 0x48), "blob_off": pos, "blob_len": n - pos,
        "tail": n - pos - size, "strings": strings, "pred": pred,
    }


# ---------------- gt cross-check (M5 §4 rules) ----------------

_EQV = {
    "FAST_CONCAT": "CONCAT", "DO_UCALL": "DO_FCALL", "DO_FCALL_BY_NAME": "DO_FCALL",
    "SEND_VAL": "SEND_VAL_EX", "SEND_VAR": "SEND_VAR_EX",
}


def gt_sections(gt_text: str) -> dict[str, list[str]]:
    secs: dict[str, list[str]] = {}
    cur = None
    for line in gt_text.split("\n"):
        t = line.strip()
        if t and t.endswith(":") and _GT_HDR.match(t):
            cur = t
            secs[cur] = []
        elif cur is not None and _GT_LINE.match(line):
            secs[cur].append(line.strip())
    return secs


_GT_HDR = re.compile(r"^([A-Za-z_$][A-Za-z0-9_:]*)?:$")
_GT_LINE = re.compile(r"^\s*\d{4}\s")


def gt_check(nodes: list[dict], gtlines: list[str]) -> tuple[int, int, int, list[str]]:
    """Subsequence alignment with the M5-HANDLERS §4 compilation rules.

    Returns (ok, total_nodes, rule_expanded, misses)."""
    ok = 0
    tot = 0
    extra = 0
    miss: list[str] = []
    g = 0
    for n in nodes:
        f = n["trueop"] if n["trueop"] is not None else n["final"]
        tot += 1
        if f is None:
            miss.append(f"MISS n{n['i']:04d}: wire=no-ktab gt=")
            continue
        mine = OPNAMES.get(f, f"op{f}")
        gtname = None
        if g < len(gtlines):
            tok = gtlines[g].split()
            tok = tok[1:]  # the 4-digit line number
            if len(tok) > 1 and tok[1] == "=":
                tok = tok[2:]
            gtname = tok[0] if tok else None
        if gtname is not None and (gtname == mine or _EQV.get(gtname) == mine):
            ok += 1
            g += 1
        elif mine == "VERIFY_RETURN_TYPE":
            extra += 1
        elif mine == "CATCH" and g > 0:
            extra += 1
        elif mine == "JMP" and gtname == "CATCH":
            ok += 1
            g += 1
        elif gtname is not None and gtname == "RETURN" and mine == "JMP":
            ok += 1
            g += 1
        elif gtname is None:
            extra += 1
        else:
            miss.append(f"MISS n{n['i']:04d}: wire={mine} gt={gtname}")
            g += 1
    return ok, tot, extra, miss


# ---------------- offline keytable params ----------------


def offline_params(seed_a=None, seed_b=None, ierg=None, x=None, seeds=None,
                   desc_file=None, mainblob_file=None, desc=None):
    """Fill (seedA, seedB, ierg, x) from the offline sources (ic_wire kt_offline_params)."""
    if seed_a is None and seeds is not None:
        m = re.match(r"^(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)$", seeds.strip())
        if not m:
            raise WireError("--seeds expects 0xAABBCCDD,0x11223344")
        seed_a = int(m.group(1), 0)
        seed_b = int(m.group(2), 0)
    if desc_file is not None:
        with open(desc_file, "rb") as f:
            d = f.read()
        if len(d) < 0x30:
            raise WireError(f"cannot read --desc {desc_file} (need >= 0x30 bytes)")
        if seed_a is None:
            seed_a = u32(d, 0x14)
            seed_b = u32(d, 0x18)
        if ierg is None:
            ierg = u32(d, 0x2C)
    if mainblob_file is not None:
        with open(mainblob_file, "rb") as f:
            mb = f.read()
        if len(mb) < 0x20:
            raise WireError(f"cannot read --mainblob {mainblob_file} (need >= 0x20 bytes)")
        if ierg is None:
            ierg = u32(mb, 0x14)
        if x is None:
            x = u32(mb, 0x1C)
    if desc is not None:
        if seed_a is None:
            seed_a = desc["seedA"]
            seed_b = desc["seedB"]
    return seed_a, seed_b, ierg, x
