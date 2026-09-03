# ioncube-re

Offline ionCube research toolchain — a Python port of the frozen PHP oracles
from the authorized ionCube Loader reverse-engineering project
(`the research workspace notes`. README fix: no absolute personal paths, with the two benchmark-driven
emitter gaps closed (interned-name resolution and arg_info typed
signatures). Pure stdlib at runtime; the loader is **never** executed.

    uv sync
    uv run pytest                      # the full validation matrix (needs the
                                       # research workspace + php for the oracle
                                       # comparisons; skips gracefully without)
    uv run ioncube-re lift FILE        # encoded file -> readable PHP listing

## The lift package (the KISS/SOLID refactor, notes/REFACTOR.md)

```
src/ioncube_re/lift/
├── model.py        # dataclasses: Node/Operand/Component/LiftContext — the shared vocabulary
├── analysis.py     # context-build passes: opcode map, +2 garble, jt calibration, +4 VAR reads
├── registry.py     # HANDLERS dict + @opcode_handler — new opcode = new entry, zero core edits
├── operand.py      # OperandRenderer (temps/CVs/refs → text) + the pure literal helpers
├── collectors.py   # call/NEW/array-literal expression collection (the DO stopping point)
├── structurer.py   # try/if/else/return/jumps + break/continue levels + ternary + goto mode
├── loops.py        # while forms (priming, do-while) + foreach (key-in-temp fold)
├── switches.py     # the switch family: CASE chains, jumptable headers, table fallback
├── emitter.py      # the walk: emit_region/emit_node dispatch (no family logic)
├── wires.py        # sub-wire scan + stream string extraction
├── sources.py      # opcode-source resolution (m5 captures, offline keytable)
├── signature.py    # parameter/type metadata + param_list
├── pipeline.py     # lift_file: component discovery → assembly → listing
└── handlers/       # one module per opcode family (arithmetic/arrays/calls/
                    # control/objects/variables/misc), ~≤250 lines each
```

Every module ≤250 lines; the decode layers (container/stream/wire/crypto)
are frozen and untouched by the refactor.

## Commands (mirroring the PHP CLIs)

| command | PHP counterpart | what it does |
|---|---|---|
| `ioncube-re decrypt FILE [--out P] [--verify REF...]` | `ic_decrypt.php decrypt / --verify` | eval chain: custom-b64 → escdec K → pbl → adler(a0=17)+MD4-fold verify → X3_(5) keystream → main blob |
| `ioncube-re key FILE...` | `ic_decrypt.php key` | K / len / seed / stream seeds per file |
| `ioncube-re component CIPHER --key eval\|HEX` | `ic_decrypt.php component` | layer-B component decrypt (17-byte eval key) |
| `ioncube-re stream decode\|decode-raw\|components\|prod\|verify\|verify-raw` | `ic_stream.php` | frame codec + raw DEFLATE; production ICB0 multi-version chunks |
| `ioncube-re wire [--ktab K] [--arena A] [--offline --seeds A,B --ierg 0x.. \| --stream --mainblob B] [--gt GT] FILE...` | `ic_wire.php` | wire-grammar walk, node assembly, offline keytable demask, gt cross-check |
| `ioncube-re lift FILE [--chunk N] [--gt GT] [--no-auto] [--m5-dir D] [--valid-php]` | `ic_lift.php` | oplines → PHP source (typed signatures, interned names, no CONCAT parens, switch/break/ternary/priming structurer, opt-in goto-label fallback) |

Exit codes match the oracles: 0 ok, 1 usage/io, 2 verification/walk failure.
`wire`'s stdout is **byte-identical** to `php legacy-php/ic_wire.php` (the opline
parity surface); decrypt/stream/lift print close-but-not-identical reports
(the artifacts they write are byte-exact).

Deviations from the PHP CLIs (documented): the oracles' leading-dash
subcommands (`--verify`) are flags here; the m5 auto-discovery root comes
from `--m5-dir` / `$IONCUBE_RE_M5_DIR` instead of a hardcoded relative path.

## Loader-version support matrix

| what | supported | evidence |
|---|---|---|
| Loader build | 15.5.0 family (`ioncube_loader_lin_8.1.so`, SHA256 `380f2ecad4ba295f66ebd88a758b55a75fc567b17b852e95f4788b0b588ebf98`, Ghidra-analyzed) | M4–M6 notes; hash asserted in tests |
| PHP targets | 8.1 (eval), 8.1/8.2/8.3/8.4 (production chunks) | the 11 eval components + 455-file CE corpus (3 chunks each) |
| Containers | "basic" eval container (magic dispatch `0x4ff571b7`) + production ICB0 multi-version | M4 / M5-PROD |
| Wire grammar | sig mode (v>5, eval 8.1 + CE 8.4 chunks) and nosig mode (v≤5, CE 8.2/8.3 chunks), auto-detected | M6-OPERANDS §1.1 |
| Opcode table | PHP 8.1 names (201) | php81 container binary |
| Offline keytable | MWC6^ierg formula — ClientExec generation + eval; **Blesta's older generation fails the validation gate** (wire-only lift) | M6-KEYTAB |

## Validation summary (all asserted in `tests/`)

- **Crypto** byte-exact vs the live gdb captures: K/escdec, pbl ciphers,
  adler17, MD4-fold = 120, the 172/172 main blobs, 368/368 component cipher,
  11/11 offline keytables.
- **Stream** byte-exact: marker81 1007/1007 vs the readerA concatenation;
  python vs `php legacy-php/ic_stream.php` on marker81 + 3 CE files + 1 blesta file
  (streams, component blobs, plains, and the frame-codec **intermediates**
  — the latter via a /tmp PHP harness that eval-loads the frozen library).
- **Wire**: full stdout byte-identical to `php legacy-php/ic_wire.php --offline` on
  all 11 eval wires + CE streams; the 11-component gt table (105 gt oplines +
  16 rule-expanded = 121/121 nodes, zero MISS); the CE 17-file × 3-chunk
  walk==EOF sweep with every demasked final in the opcode range.
- **Lift**: marker81 lifts to `function hello(string $who): string { return
  'hi ' . $who; }` + `echo hello('AAAA_marker_0001');` (semantic match to the
  ground-truth marker.php, matching decodephp.io's output); cron.php matches
  decodephp's production preview statement-for-statement (§9.3, 6/6).
- **Corpus sweep**: the CLI chain exits 0 on all 461 encoded files
  (455 ClientExec + 6 Blesta).

## Honest limitations (full list: `notes/PYTHON-PORT.md`)

- wD0-node opcode recovery for eval v>5 wires still needs the arena capture
  (the offline ktab sig-gates those nodes to placeholders); the CE encoder
  leaves the true opcode in the dance value, so production lifts fully.
- Blesta's encoder generation fails the offline-keytable validation gate →
  structure + literals + try/catch only (per-node placeholders).
- The wire parser does not descend into nested sub-function wires (the
  grammar's [sf] section): 5 CE corpus files end their walk early —
  byte-identical behavior to the PHP oracle, which does the same.
- Interned names resolve from the full validated 591+2-entry loader table
  (4308 corpus references, zero unresolved); indices beyond the table or
  with a length mismatch keep the `/*interned-N len=L*/` placeholder —
  never a guess.
- M6's 18 imperfect operand conversions (INIT_FCALL frame sizes, wD0-node
  jump-target rewrites, 0x12/0x22 result flags) carry over unchanged.
- Serialized-array zvals recover their string elements only.
- Round-trip validity is not a goal: this is a decompiler listing.

## Dependencies

`z3-solver` and `capstone` are declared per the project spec (the research
lineage: the M6 z3 wire-mask solve and the loader disassembly). The shipped
deterministic ports import neither — they run on the Python stdlib alone
(hashlib has no MD4 on OpenSSL 3, so `crypto/md4fold.py` carries a compact
pure-Python RFC-1186 MD4, cross-checked against PHP's `hash('md4')`).
