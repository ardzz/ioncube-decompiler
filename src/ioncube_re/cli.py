"""argparse CLI: subcommands decrypt|key|component|stream|wire|lift —
mirroring the frozen PHP CLIs (legacy-php/ic_decrypt.php, ic_stream.php, ic_wire.php,
ic_lift.php). `uv run ioncube-re lift FILE`.

Deviations from the PHP CLIs (documented):
  - the PHP tools' leading-dash subcommands (ic_decrypt --verify, ic_stream
    --verify / --verify-raw) are flag forms here: `decrypt --verify FILE REFS`,
    `stream verify FILE GLOB`, `stream verify-raw RAW SEED GLOB`;
  - decrypt/stream/lift print a close-but-not-identical report format (the
    artifacts are byte-exact; the wire subcommand's stdout is byte-identical
    to the PHP oracle — the opline parity surface);
  - the m5 auto-discovery root defaults to $IONCUBE_RE_M5_DIR, then the
    workspace dumps root $IONCUBE_RE_WORKSPACE/work/dumps/m5 (the PHP tool
    hardcodes __DIR__/../work/dumps/m5); override with --m5-dir.
"""

import argparse
import os
import re
import sys
from glob import glob
from typing import NoReturn

from . import __version__
from .container import decrypt_file, prod_chunks, u32
from .crypto.escdec import escdec
from .crypto.layerb import EVAL_KEY, component_decrypt
from .lint import LINT_FAIL, php_lint
from .lift.pipeline import PipelineError, lift_file
from .stream import (
    StreamError,
    decode_raw,
    prod_decode_file,
    stream_of_file,
    verify_stream,
)
from .wire import (
    WireError,
    fmt_node,
    gt_check,
    gt_sections,
    offline_params,
    parse_stream_desc,
    parse_wire,
    render_wire_report,
)
from .crypto.keytable import kt_generate

FAIL = 1
VERIFY_FAIL = 2


def _die(msg: str, code: int = FAIL) -> NoReturn:
    print(f"ioncube-re: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _out_bytes(s: str):
    sys.stdout.buffer.write(s.encode("latin-1", errors="replace"))
    sys.stdout.buffer.flush()


# ---------------- decrypt / key / component ----------------


def cmd_decrypt(a):
    if a.verify:
        return _decrypt_verify(a)
    out_prefix = a.out
    for f in a.files:
        try:
            r = decrypt_file(f)
        except (ValueError, OSError) as e:
            _die(str(e))
        print(f"== {f}")
        print(f"  payload         {len(r['payload'])} bytes (custom base64)")
        print(f"  magic           0x{r['magic']:08x} -> dispatch 0x4ff571b7 (basic)")
        print(f"  key K           {r['key_hex']} (escdec of 24-byte header)")
        print(f"  blob len        {r['len']}   seed  0x{r['seed']:08x}")
        print(f"  raw region      {r['raw_region']} (adler scope)")
        print(f"  adler(a0=17)    computed 0x{r['adler_computed']:08x}  "
              f"stored 0x{r['adler_stored']:08x}  {'OK' if r['adler_ok'] else 'FAIL'}")
        print(f"  rol3key         {r['rol3key'].hex().upper()}")
        print(f"  keystream       X3_(5) CMWC-hybrid seeded 0x{r['seed']:08x}, "
              f"{r['len'] - 16} bytes")
        print(f"  MD4 fold        {r['md4_fold']} (want 120)  "
              f"{'OK' if r['md4_fold'] == 120 else 'FAIL'}")
        off, end = r["stream_region"]
        print(f"  stream seed     0x{r['stream_seed']:08x}   reseed 0x{r['reseed']:08x}   "
              f"region payload[{off}..{end})")
        base = re.sub(r"[^a-z0-9]+", "_", os.path.basename(f)[:-4] or os.path.basename(f), flags=re.I)
        pf = f"{out_prefix}.{base}.mainblob.bin"
        with open(pf, "wb") as fh:
            fh.write(r["plain"])
        cf = f"{out_prefix}.{base}.cipher.bin"
        with open(cf, "wb") as fh:
            fh.write(r["cipher"])
        print(f"  wrote           {pf} ({len(r['plain'])} B decrypted), "
              f"{cf} ({len(r['cipher'])} B ciphertext)")
        print(f"  VERDICT         {'DECRYPTED+VERIFIED' if r['ok'] else 'VERIFICATION FAILED'}")
        if not r["ok"]:
            raise SystemExit(VERIFY_FAIL)
    return 0


def _decrypt_verify(a):
    if len(a.files) < 2:
        _die("decrypt --verify FILE REF...")
    f = a.files[0]
    try:
        r = decrypt_file(f)
    except (ValueError, OSError) as e:
        _die(str(e))
    if not r["ok"]:
        print(f"chain verification failed for {f}")
        raise SystemExit(VERIFY_FAIL)
    plain = r["plain"]
    ok = False
    tried = 0
    for ref in a.files[1:]:
        try:
            with open(ref, "rb") as fh:
                dump = fh.read()
        except OSError:
            print(f"cannot read reference {ref}")
            continue
        tried += 1
        n = min(len(dump), len(plain))
        mism = sum(1 for i in range(n) if plain[i] != dump[i])
        first = next((i for i in range(n) if plain[i] != dump[i]), -1)
        if mism == 0 and len(dump) >= len(plain):
            print(f"VERIFY {os.path.basename(f)}: {len(plain)}/{len(plain)} bytes MATCH (dump {ref})")
            ok = True
        else:
            print(f"VERIFY {os.path.basename(f)} vs {ref}: {n - mism}/{n} match, "
                  f"first mismatch at {first}")
            full = bytearray(r["cipher"])
            full[: len(plain)] = plain
            n2 = min(len(dump), len(full))
            mism2 = sum(1 for i in range(n2) if full[i] != dump[i])
            if mism2 == 0 and len(dump) == len(full):
                print(f"VERIFY {os.path.basename(f)}: FULL in-place buffer "
                      f"(plain+rol3 tail) {n2}/{n2} bytes MATCH")
                ok = True
    if not tried:
        _die("no readable reference dumps")
    raise SystemExit(0 if ok else VERIFY_FAIL)


def cmd_key(a):
    if not a.files:
        _die("key FILE...")
    for f in a.files:
        try:
            r = decrypt_file(f)
        except (ValueError, OSError) as e:
            _die(str(e))
        print("%-24s K=%s len=%d seed=0x%08x streamseed=0x%08x reseed=0x%08x "
              "adler=0x%08x md4fold=%s"
              % (os.path.basename(f), r["key_hex"], r["len"], r["seed"],
                 r["stream_seed"], r["reseed"], r["adler_computed"], r["md4_fold"]))
    return 0


def cmd_component(a):
    if not a.cipherfile:
        _die("component CIPHERFILE --key HEX|eval")
    try:
        with open(a.cipherfile, "rb") as fh:
            cipher = fh.read()
    except OSError as e:
        _die(str(e))
    key = (b"\x01" * 16 + b"\x00") if a.key.lower() == "eval" else bytes.fromhex(a.key)
    plain = component_decrypt(cipher, key)
    out = re.sub(r"\.[^.]*$", "", a.cipherfile) + ".dec.bin"
    with open(out, "wb") as fh:
        fh.write(plain)
    print(f"component decrypt: {len(cipher)} B cipher -> {len(plain)} B plain "
          f"(key {key.hex().upper()}) -> {out}")
    for needle in (b"AAAA_marker", b"hello", b"who", b"hi "):
        if needle in plain:
            print(f"  literal visible: {needle.decode()}")
    return 0


# ---------------- stream ----------------


def cmd_stream(a) -> int:
    if a.cmd == "decode":
        try:
            r = stream_of_file(a.files[0])
        except (StreamError, ValueError, OSError) as e:
            _die(str(e))
        print(f"{a.files[0]}: region @payload+{r['region_off']} ({len(r['raw'])} B), "
              f"seed 0x{r['seed']:08x}, {r['frames']} frames, {r['checkpoints']} adler "
              f"checkpoints OK, intermediate {len(r['inter'])} B -> stream {len(r['stream'])} B")
        out = a.out or re.sub(r"\.php$", "", a.files[0], flags=re.I) + ".stream.bin"
        with open(out, "wb") as fh:
            fh.write(r["stream"])
        print(f"wrote {out} ({len(r['stream'])} B)")
        return 0
    if a.cmd == "decode-raw":
        try:
            with open(a.files[0], "rb") as fh:
                raw = fh.read()
            r = decode_raw(raw, int(a.files[1], 16))
        except (StreamError, ValueError, OSError) as e:
            _die(str(e))
        print(f"{a.files[0]}: {len(raw)} B raw, seed 0x{r['seed']:08x}, {r['frames']} frames, "
              f"{r['checkpoints']} adler checkpoints OK, intermediate {len(r['inter'])} B "
              f"-> stream {len(r['stream'])} B")
        out = a.out or re.sub(r"\.[^.]*$", "", a.files[0]) + ".stream.bin"
        with open(out, "wb") as fh:
            fh.write(r["stream"])
        print(f"wrote {out} ({len(r['stream'])} B)")
        return 0
    if a.cmd == "components":
        try:
            r = stream_of_file(a.files[0])
            from .container import component_blob

            coff, size, blob = component_blob(r["stream"])
        except (StreamError, ValueError, OSError) as e:
            _die(str(e))
        stem = a.out or re.sub(r"\.php$", "", a.files[0], flags=re.I)
        ccp = f"{stem}.cc.bin"
        with open(ccp, "wb") as fh:
            fh.write(blob)
        print(f"{a.files[0]}: stream {len(r['stream'])} B, component ciphertext at "
              f"[0x{coff:x}..0x{coff + size:x}) ({size} B) -> {ccp}")
        plain = component_decrypt(blob, EVAL_KEY)
        cpp = f"{stem}.cplain.bin"
        with open(cpp, "wb") as fh:
            fh.write(plain)
        print(f"layer-B decrypt (eval key 01x16+00): {len(plain)} B -> {cpp}")
        print("visible literals:")
        for m in re.finditer(rb"[\x20-\x7e]{4,}", plain):
            run = m.group(0).strip(b"\x00")
            if len(run) >= 4:
                print(f'  "{run.decode("latin-1")}"')
        return 0
    if a.cmd == "prod":
        only = a.chunk if a.chunk and a.chunk >= 1 else None
        try:
            r = prod_decode_file(a.files[0], only)
        except (StreamError, ValueError, OSError) as e:
            _die(str(e))
        fieldstr = " ".join(f"{v}:{h:x}" for v, h in r["fields"])
        print(f"{a.files[0]}: ICB0 {fieldstr}, {len(r['chunks'])} chunks")
        stem = a.out or re.sub(r"\.php$", "", a.files[0], flags=re.I)
        allok = True
        for c in r["chunks"]:
            n = c["num"]
            ad = "OK" if c["adler_ok"] else "**FAIL**"
            blob = (f"{c['blob_method']}@0x{c['blob_off']:x} {len(c['blob'])} B"
                    if "blob" in c else "NOT FOUND")
            print(f"  chunk{n}: {c['region_off'] + c['region_len']} B container, "
                  f"len={c['len']} seed=0x{c['seed']:08x}, adler {ad}, "
                  f"SEED=0x{c['stream_seed']:08x} RESEED=0x{c['reseed']:08x}")
            print(f"    region [{c['region_off']}..{c['region_off'] + c['region_len']}): "
                  f"{c['frames']} frames, {c['ckpts']} adler checkpoints OK, "
                  f"intermediate {len(c['inter'])} B -> stream {len(c['stream'])} B "
                  f"(gzinflate OK)")
            print(f"    component ciphertext {blob}", end="")
            if "plain" in c:
                lits = re.findall(rb"[\x20-\x7e]{4,}", c["plain"])[:6]
                print(f" -> layer-B decrypt (eval key): {len(c['plain'])} B plain")
                print(f"       literals: {' | '.join(l.decode('latin-1') for l in lits)}")
            else:
                print()
                allok = False
            if not c["adler_ok"]:
                allok = False
            if a.out or a.chunk:
                with open(f"{stem}.c{n}.stream.bin", "wb") as fh:
                    fh.write(c["stream"])
                if "blob" in c:
                    with open(f"{stem}.c{n}.cc.bin", "wb") as fh:
                        fh.write(c["blob"])
                    with open(f"{stem}.c{n}.cplain.bin", "wb") as fh:
                        fh.write(c["plain"])
        raise SystemExit(0 if allok else VERIFY_FAIL)
    if a.cmd == "verify":
        try:
            r = stream_of_file(a.files[0])
        except (StreamError, ValueError, OSError) as e:
            _die(str(e))
        print(f"{a.files[0]}: intermediate {len(r['inter'])} B (adler {r['frame_adler']}, "
              f"{r['checkpoints']} checkpoints OK) -> stream {len(r['stream'])} B")
        files = sorted(glob(a.files[1])) if a.files[1] else []
        if not files:
            _die(f"no files match {a.files[1]}")
        ok, rep = verify_stream(r["stream"], files)
        print(rep, end="")
        raise SystemExit(0 if ok else VERIFY_FAIL)
    if a.cmd == "verify-raw":
        try:
            with open(a.files[0], "rb") as fh:
                raw = fh.read()
            r = decode_raw(raw, int(a.files[1], 16))
        except (StreamError, ValueError, OSError) as e:
            _die(str(e))
        print(f"{a.files[0]}: {len(raw)} B raw, seed 0x{r['seed']:08x}, "
              f"{r['checkpoints']} adler checkpoints OK -> stream {len(r['stream'])} B")
        files = sorted(glob(a.files[2])) if len(a.files) > 2 else []
        if not files:
            _die(f"no files match {a.files[2]}")
        ok, rep = verify_stream(r["stream"], files)
        print(rep, end="")
        raise SystemExit(0 if ok else VERIFY_FAIL)
    _die("unknown stream subcommand")


# ---------------- wire ----------------


def cmd_wire(a):
    if not a.files:
        _die("usage: ioncube-re wire [--ktab K] [--gt gt.txt [--gtsec SEC]] [--arena A] "
             "[--component] [--stream] [--offline] FILE...")
    if a.offline and a.ktab:
        _die("--offline and --ktab are exclusive")
    exit_code = 0
    gtidx = 0
    for f in a.files:
        try:
            with open(f, "rb") as fh:
                w = fh.read()
        except OSError as e:
            print(f"ic_wire: cannot read {f}", file=sys.stderr)
            exit_code = 1
            continue
        desc = None
        if a.stream:
            desc = parse_stream_desc(w)
            if desc is None:
                print(f"ic_wire: {f}: no 1ea1e5ae ciphertext signature in the first "
                      f"0x4c+0x400 bytes — not a component stream?", file=sys.stderr)
                exit_code = 2
                continue
            blob = w[desc["blob_off"] : desc["blob_off"] + desc["size"]]
            if len(blob) < desc["size"]:
                print(f"ic_wire: {f}: blob truncated ({desc['size']} needed, "
                      f"{len(blob)} present)", file=sys.stderr)
                exit_code = 2
                continue
            w = component_decrypt(blob, EVAL_KEY)
            _out_bytes("   stream-desc: size=%d seedA=%08x seedB=%08x blob@0x%x "
                       "(pred 0x%x %s) tail=%d strings=[%s]\n"
                       % (desc["size"], desc["seedA"], desc["seedB"], desc["blob_off"],
                          desc["pred"], "OK" if desc["blob_off"] == desc["pred"] else "DIFF",
                          desc["tail"],
                          ",".join('"%s"' % s.decode("latin-1") for s in desc["strings"])))
        if a.component:
            w = component_decrypt(w, EVAL_KEY)
        kt = None
        if a.ktab:
            try:
                with open(a.ktab, "rb") as fh:
                    kt = fh.read()
            except OSError:
                kt = None
        fxoff = 2  # the eval encoder's K2 offset
        if a.offline:
            try:
                sa, sb, erg, xo = offline_params(
                    seeds=a.seeds, desc_file=a.desc, mainblob_file=a.mainblob,
                    ierg=(int(a.ierg, 0) if a.ierg else None),
                    x=(int(a.x, 0) if a.x else None), desc=desc)
            except (WireError, OSError) as e:
                print(f"ic_wire: {e}", file=sys.stderr)
                exit_code = 1
                continue
            if sa is None or sb is None or erg is None:
                print(f"ic_wire: {f}: --offline needs seeds (--seeds|--desc|--stream) "
                      f"and ierg (--ierg|--desc|--mainblob)", file=sys.stderr)
                exit_code = 1
                continue
            xo = xo if xo is not None else 2
            if len(w) < 0x34:
                print(f"ic_wire: {f} too short for THR", file=sys.stderr)
                exit_code = 1
                continue
            thr0 = u32(w, 0x30)
            kt = kt_generate(sa, sb, erg, thr0)
            fxoff = xo
            _out_bytes("   offline-ktab: seeds=(0x%08x,0x%08x) ierg=0x%08x thr=%d x=%d "
                       "-> %d bytes\n" % (sa, sb, erg, thr0, fxoff, len(kt)))
            if a.ktab_out:
                with open(a.ktab_out, "wb") as fh:
                    fh.write(kt)
        arena = None
        if a.arena:
            try:
                with open(a.arena, "rb") as fh:
                    arena = fh.read()
                if kt is None:
                    m = re.search(r"arena_(\d+)", os.path.basename(a.arena))
                    if m:
                        g = sorted(glob(os.path.join(os.path.dirname(a.arena),
                                                     f"ktab_{m.group(1)}_*")))
                        if g:
                            with open(g[0], "rb") as fh:
                                kt = fh.read()
            except OSError:
                arena = None
        try:
            r = parse_wire(w, kt, arena, fxoff)
        except WireError as e:
            print(f"ic_wire: {f}: {e}", file=sys.stderr)
            exit_code = 2
            continue
        for line in render_wire_report(r, os.path.basename(f)):
            _out_bytes(line + "\n")
        if r["end"] != r["len"]:
            exit_code = 2
        if a.gt:
            try:
                with open(a.gt, "r") as fh:
                    gt_text = fh.read()
            except OSError:
                print(f"ic_wire: cannot read {a.gt}", file=sys.stderr)
                exit_code = 1
                continue
            secs = gt_sections(gt_text)
            secnames = list(secs)
            sec = None
            if a.gtsec and a.gtsec in secs:
                sec = a.gtsec
            elif a.gtsec:
                for sn in secnames:
                    if a.gtsec in sn:
                        sec = sn
                        break
            elif gtidx < len(secnames):
                sec = secnames[gtidx]
            gtl = secs.get(sec, [])
            _out_bytes("   gt-section: %s (%d oplines)\n" % (sec or "?", len(gtl)))
            ok, tot, extra, miss = gt_check(r["nodes"], gtl)
            _out_bytes("   gt: opcode-name match %d/%d nodes "
                       "(%d rule-expanded epilogue/catch nodes)\n" % (ok, tot, extra))
            for m in miss:
                _out_bytes("      %s\n" % m)
            if miss:
                exit_code = 2
        gtidx += 1
    raise SystemExit(exit_code)


# ---------------- lift ----------------


def _default_m5_dir() -> str:
    # the PHP tool's hardcoded __DIR__/../work/dumps/m5, env-overridable
    d = os.environ.get("IONCUBE_RE_M5_DIR")
    if d:
        return d
    ws = os.environ.get("IONCUBE_RE_WORKSPACE", "/home/reky/workspaces/cylab/ioncube")
    return os.path.join(ws, "work", "dumps", "m5")


def cmd_lift(a):
    if not a.files:
        _die("usage: ioncube-re lift FILE [--chunk N] [--arena A] [--ktab K] "
             "[--gt GTFILE] [--no-auto] [--m5-dir DIR] [--valid-php] [--no-lint]")
    rc = 0
    for FILE in a.files:
        try:
            r = lift_file(FILE, chunk=a.chunk, arena=a.arena, ktab=a.ktab, gt=a.gt,
                          auto=not a.no_auto, m5dir=a.m5_dir or _default_m5_dir(),
                          valid_php=a.valid_php)
        except (PipelineError, StreamError, ValueError, OSError) as e:
            print(f"ic_lift: {e}", file=sys.stderr)
            raise SystemExit(VERIFY_FAIL)
        for line in r["stderr"]:
            print(line, file=sys.stderr)
        sys.stdout.write(r["text"])
        for line in r["gt"]:
            print(line)
        if a.lint:
            # the lint report is the command's FINAL output line
            report, ok = php_lint(r["text"])
            print(report)
            if not ok:
                rc = LINT_FAIL
    return rc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ioncube-re", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"ioncube-re {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decrypt", help="eval chain: decrypt FILE (writes .mainblob/.cipher)")
    d.add_argument("files", nargs="+")
    d.add_argument("--out", default="ic_decrypted")
    d.add_argument("--verify", action="store_true",
                   help="verify files[0] against files[1:] reference dumps")
    d.set_defaults(fn=cmd_decrypt)

    k = sub.add_parser("key", help="show K / len / seed / stream seeds per file")
    k.add_argument("files", nargs="+")
    k.set_defaults(fn=cmd_key)

    c = sub.add_parser("component", help="layer-B decrypt of a captured component blob")
    c.add_argument("cipherfile")
    c.add_argument("--key", default="eval")
    c.set_defaults(fn=cmd_component)

    s = sub.add_parser("stream", help="frame codec + deflate (ic_stream)")
    ss = s.add_subparsers(dest="cmd", required=True)
    for name, help_ in (("decode", "encoded .php -> decoded stream"),
                        ("decode-raw", "captured raw region + STREAM SEED -> stream"),
                        ("components", "decode + component blob + layer-B decrypt"),
                        ("prod", "production ICB0 multi-version files"),
                        ("verify", "decode + byte-compare vs readerA dumps"),
                        ("verify-raw", "raw + seed + byte-compare")):
        sp = ss.add_parser(name, help=help_)
        sp.add_argument("files", nargs="+")
        sp.add_argument("--out", default=None)
        sp.add_argument("--chunk", type=int, default=None)
        sp.set_defaults(fn=cmd_stream)

    w = sub.add_parser("wire", help="wire grammar walk + node assembly (ic_wire)")
    w.add_argument("files", nargs="+")
    w.add_argument("--ktab")
    w.add_argument("--gt")
    w.add_argument("--gtsec")
    w.add_argument("--arena")
    w.add_argument("--component", action="store_true")
    w.add_argument("--stream", action="store_true")
    w.add_argument("--offline", action="store_true")
    w.add_argument("--seeds")
    w.add_argument("--ierg")
    w.add_argument("--x")
    w.add_argument("--desc")
    w.add_argument("--mainblob")
    w.add_argument("--ktab-out")
    w.set_defaults(fn=cmd_wire)

    l = sub.add_parser("lift", help="decoded oplines -> readable PHP source (ic_lift)")
    l.add_argument("files", nargs="+")
    l.add_argument("--chunk", type=int, default=1)
    l.add_argument("--arena")
    l.add_argument("--ktab")
    l.add_argument("--gt")
    l.add_argument("--no-auto", action="store_true")
    l.add_argument("--m5-dir", default=None)
    l.add_argument("--valid-php", action="store_true",
                   help="adopt the goto-label fallback for irreducible flow "
                        "(runnable output, unfaithful to the source shape — "
                        "default is the faithful comment policy)")
    l.add_argument("--lint", action=argparse.BooleanOptionalAction, default=True,
                   help="php -l the rendered output (php81-test container; "
                        "degraded pure-Python check when unavailable). "
                        "Default: on; disable with --no-lint. Exit code 3 on "
                        "lint failure.")
    l.set_defaults(fn=cmd_lift)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    rc = a.fn(a)
    raise SystemExit(rc or 0)


if __name__ == "__main__":
    main()
