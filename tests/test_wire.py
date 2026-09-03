"""Wire-layer tests: the 11-component gt table, ktab parity, CE wire walks.

1. ktab byte-exact on the m5 ktab dumps (11/11 — covered in test_crypto with
   the full table; here via the CLI --ktab-out artifact);
2. the 11-component gt table: oplines + operands vs the gt dumps (the M6 §4
   numbers, zero MISS rows), through the offline keytable + arena paths;
3. opline parity: python vs `php legacy-php/ic_wire.php --offline` on the same
   wires — the full stdout (header, HDRF, pool, zvals, node lines, sig line)
   is byte-identical;
4. the CE 17-file wire walk: every chunk walks to EOF with a valid checksum
   and every demasked final in the opcode range (the M6-KEYTAB §5.3 sweep).
"""

import glob
import os
import re

import pytest

from ioncube_re.container import u32
from ioncube_re.crypto.keytable import kt_generate
from ioncube_re.crypto.layerb import EVAL_KEY, component_decrypt
from ioncube_re.wire import gt_check, gt_sections, parse_stream_desc, parse_wire

from conftest import M5, M6, M6KT, WORK, WORKSPACE, requires_php, requires_workspace, run_php

BIN = os.path.join(WORKSPACE, "bin")

# (sample, wire glob, gt section, arena idx, expected ok, expected total, expected
#  rule-expanded) — the arena index mirrors work/dumps/m6/m6_validate.sh pairing
_GT_TABLE = [
    ("marker81", "readerA_0020_*.dec.bin", "gt_marker.txt", "$_main:", 0, 5, 5, 0),
    ("marker81", "readerA_0052_*_438B.bin", "gt_marker.txt", "hello:", 1, 3, 6, 3),
    ("fresh81", "readerA_0020_*.dec.bin", "gt_fresh_src.txt", "$_main:", 0, 5, 5, 0),
    ("fresh81", "readerA_0062_*_439B.bin", "gt_fresh_src.txt", "Greeter::hi:", 1, 3, 6, 3),
    ("gt_diverse1", "readerA_0030_*.dec.bin", "gt_gt_diverse1.txt", "$_main:", 0, 21, 21, 0),
    ("gt_diverse2", "readerA_0030_*.dec.bin", "gt_gt_diverse2.txt", "$_main:", 0, 39, 40, 1),
    ("gt_diverse2", "readerA_0068_*_514B.bin", "gt_gt_diverse2.txt", "join2:", 1, 5, 8, 3),
    ("gt_diverse3", "readerA_0022_*.dec.bin", "gt_gt_diverse3.txt", "$_main:", 0, 14, 14, 0),
    ("gt_diverse3", "readerA_0114_*_367B.bin", "gt_gt_diverse3.txt", "Dog::__construct:", 1, 4, 4, 0),
    ("gt_diverse3", "readerA_0139_*_470B.bin", "gt_gt_diverse3.txt", "Dog::label:", 2, 4, 7, 3),
    ("gt_diverse3", "readerA_0058_*_376B.bin", "gt_gt_diverse3.txt", "Animal::label:", 3, 2, 5, 3),
]

_IERG = {"marker81": 0x363A68, "fresh81": 0x365721, "gt_diverse1": 0x36850D,
         "gt_diverse2": 0x36850D, "gt_diverse3": 0x36850D}


def _sample_dir(sample):
    return f"{M5}/{sample}"


def _wire_path(sample, pattern):
    return sorted(glob.glob(f"{M5}/{sample}/{pattern}"))[0]


@requires_workspace
@pytest.mark.parametrize(
    "sample,wire_glob,gtfile,gtsec,aidx,ok,tot,extra",
    _GT_TABLE,
    ids=[r[0] + ":" + r[3].rstrip(":") for r in _GT_TABLE],
)
def test_gt_table_11_components(sample, wire_glob, gtfile, gtsec, aidx, ok, tot, extra):
    """The M6 §4 validation table, via offline ktab + the arena for wD0 nodes."""
    wire = open(_wire_path(sample, wire_glob), "rb").read()
    seeds = _component_seeds(sample, wire)
    arena = open(sorted(glob.glob(f"{M5}/{sample}/arena_*"))[aidx], "rb").read()
    kt_live = open(sorted(glob.glob(f"{M5}/{sample}/ktab_*"))[aidx], "rb").read()
    kt = kt_generate(seeds[0], seeds[1], _IERG[sample], u32(wire, 0x30))
    r = parse_wire(wire, kt_live, arena, 2)
    secs = gt_sections(open(f"{M5}/{gtfile}").read())
    got_ok, got_tot, got_extra, miss = gt_check(r["nodes"], secs[gtsec])
    assert (got_ok, got_tot, got_extra) == (ok, tot, extra), miss
    assert miss == []
    # the offline keytable must equal the live dump prefix (ktab parity)
    assert kt[: len(kt_live)] == kt_live


def _component_seeds(sample, wire):
    """seedA/seedB from the readerA read sequence: the [size][seedA][seedB]
    triple preceding each component's wire (m6kt_eval.py's reader_reads)."""
    import struct

    files = sorted(
        [f for f in glob.glob(f"{M5}/{sample}/readerA_*.bin") if not f.endswith(".dec.bin")],
        key=lambda p: int(re.search(r"readerA_(\d+)_", p).group(1)),
    )
    reads = []
    for f in files:
        m = re.search(r"_(\d+)B\.bin$", f)
        reads.append((int(m.group(1)), open(f, "rb").read()))
    n = len(wire)
    for k in range(len(reads) - 1, -1, -1):
        sz, b = reads[k]
        if sz == 4 and struct.unpack("<I", b)[0] == n and k + 2 < len(reads) \
                and reads[k + 1][0] == 4 and reads[k + 2][0] == 4:
            return (struct.unpack("<I", reads[k + 1][1])[0],
                    struct.unpack("<I", reads[k + 2][1])[0])
    # main component: the stream descriptor seeds = stream[0x08]/[0x0c]
    # (not in the readerA sequence for mains — fall back to the known table)
    raise AssertionError(f"no seed triple found for {sample} wire of {n} B")


@requires_workspace
@requires_php
@pytest.mark.parametrize(
    "sample,wire_glob,gtfile,gtsec,aidx,ok,tot,extra",
    _GT_TABLE,
    ids=[r[0] + ":" + r[3].rstrip(":") for r in _GT_TABLE],
)
def test_opline_parity_vs_php_oracle(sample, wire_glob, gtfile, gtsec, aidx, ok, tot, extra, tmp_path):
    """python wire CLI stdout == `php legacy-php/ic_wire.php --offline` stdout."""
    wire = _wire_path(sample, wire_glob)
    seeds = _component_seeds(sample, open(wire, "rb").read())
    ierg = _IERG[sample]
    seed_arg = f"0x{seeds[0]:x},0x{seeds[1]:x}"
    ierg_arg = f"0x{ierg:x}"
    rc_php, php_out, php_err = run_php(
        ["legacy-php/ic_wire.php", "--offline", "--seeds", seed_arg, "--ierg", ierg_arg, wire]
    )
    assert rc_php == 0, php_err
    from conftest import cli

    proc = cli(["wire", "--offline", "--seeds", seed_arg, "--ierg", ierg_arg, wire])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == php_out, "wire stdout differs from the PHP oracle"


_CE_17 = [
    "cron.php", "admin/index.php", "api/index.php", "install.php",
    "library/front.php", "modules/domains/models/ICanImportDomains.php",
    "modules/domains/models/MethodNotImplemented.php",
    "modules/domains/controllers/IndexController.php",
    "modules/billing/models/BillingTypeGateway.php",
    "modules/billing/models/InvoiceEntriesEntry.php",
    "modules/billing/models/TaxGateway.php", "modules/billing/models/TaxRule.php",
    "modules/billing/models/UnInvoicedListIterator.php",
    "modules/billing/models/class.gateway.plugin.php",
    "library/setup/scripts/upgrade_5_0_0RC3.php",
    "library/setup/scripts/upgrade_6_6_1a1.php",
    "library/setup/scripts/upgrade_6_7_0a2.php",
]


@requires_workspace
@pytest.mark.parametrize("rel", _CE_17)
def test_ce_17_wire_walk_eof(rel):
    """All 3 chunks of the 17 M6 CE files: walk==EOF, chk OK, offline-ktab
    finals all in the opcode range (the M6-KEYTAB §5.3 sweep)."""
    from ioncube_re.stream import prod_decode_file

    ce = os.path.join(WORK, "corpus", "clientexec", "clientexec")
    # the m6-keytab wrapper stems mix basename and path-with-underscores forms
    stems = [os.path.basename(rel), rel.replace("/", "_")]
    r = prod_decode_file(os.path.join(ce, rel))
    for c in r["chunks"]:
        n = c["num"]
        mbs = [m for st in stems for m in glob.glob(f"{M6KT}/cewrap_{st}.c{n}.*mainblob.bin")]
        assert mbs, f"mainblob for {rel} c{n}"
        mbb = open(mbs[0], "rb").read()
        ierg = u32(mbb, 0x14)
        x = u32(mbb, 0x1C)
        stream = c["stream"]
        desc = parse_stream_desc(stream)
        assert desc is not None
        blob = stream[desc["blob_off"] : desc["blob_off"] + desc["size"]]
        wire = component_decrypt(blob, EVAL_KEY)
        kt = kt_generate(desc["seedA"], desc["seedB"], ierg, u32(wire, 0x30))
        wr = parse_wire(wire, kt, None, x)
        assert wr["chk"], f"{rel} c{n}: header checksum"
        assert wr["end"] == wr["len"], f"{rel} c{n}: walk {wr['end']} != {wr['len']}"
        finals = [nn["final"] for nn in wr["nodes"] if nn["final"] is not None]
        assert finals and all(f <= 206 for f in finals), f"{rel} c{n}: finals out of range"


@requires_workspace
@requires_php
def test_ce_wire_opline_parity_vs_php(tmp_path):
    """A CE stream wire through the CLI: stdout byte-identical to PHP's
    --stream --offline --mainblob mode (cron c1/c2/c3 + api_index c3)."""
    from conftest import cli

    ce = os.path.join(WORK, "corpus", "clientexec", "clientexec")
    cases = [("cron.php", 1), ("cron.php", 2), ("cron.php", 3), ("api/index.php", 3)]
    for rel, n in cases:
        stems = [os.path.basename(rel), rel.replace("/", "_")]
        mbs = [m for st in stems for m in glob.glob(f"{M6KT}/cewrap_{st}.c{n}.*mainblob.bin")]
        assert mbs
        mb = mbs[0]
        streams = [s for st in stems for s in glob.glob(f"{M6}/ce/{st}.c{n}.stream.bin")]
        assert streams
        stream = streams[0]
        rc_php, php_out, php_err = run_php(
            ["legacy-php/ic_wire.php", "--stream", "--offline", "--mainblob", mb, stream]
        )
        assert rc_php == 0, php_err
        proc = cli(["wire", "--stream", "--offline", "--mainblob", mb, stream])
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == php_out, f"{rel} c{n}: wire stdout differs"
