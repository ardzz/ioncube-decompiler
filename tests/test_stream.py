"""Stream-layer tests: byte-exact validation against the frozen PHP oracles.

1. marker81 stream 1007/1007 vs the m4 readerA concatenation (the M5-FROB
   ground truth) — library level;
2. python vs `php legacy-php/ic_stream.php` on the same inputs (marker81 + 3 CE
   files + 1 blesta file): the stream artifacts AND the frame-codec
   intermediates byte-exact (the intermediate via a /tmp PHP harness that
   eval-loads ic_stream.php's library body — the ic_lift loader pattern);
3. the full-corpus CLI sweep: `python -m ioncube_re stream prod FILE` exit 0
   on all 461 encoded corpus files (the PHP tools' sweep, Python edition).
"""

import os
import subprocess
import sys

import pytest

from ioncube_re.container import prod_chunks, prod_container
from ioncube_re.stream import prod_decode_file, stream_of_file, verify_stream

from conftest import (
    CE,
    M4,
    M6KT,
    WORK,
    WORKSPACE,
    ce_encoded_files,
    cli,
    php_intermediate_harness,
    requires_php,
    requires_workspace,
    run_php,
)

BIN = os.path.join(WORKSPACE, "bin")


@requires_workspace
def test_marker81_stream_1007():
    import glob

    r = stream_of_file(f"{WORK}/marker81.php")
    assert len(r["stream"]) == 1007
    assert r["checkpoints"] == 1
    dumps = sorted(glob.glob(f"{M4}/marker81/readerA_*_*B.bin"))
    ok, rep = verify_stream(r["stream"], dumps)
    assert ok, rep
    assert "1007/1007 bytes MATCH — BYTE-EXACT" in rep


@requires_workspace
@requires_php
def test_marker81_byte_exact_vs_php_oracle(tmp_path):
    """decode: stream artifact + frame-codec intermediate byte-exact vs PHP."""
    php_out = tmp_path / "php.stream.bin"
    rc, out, err = run_php(
        ["legacy-php/ic_stream.php", "decode", "work/marker81.php", "--out", str(php_out)]
    )
    assert rc == 0, err
    r = stream_of_file(f"{WORK}/marker81.php")
    assert r["stream"] == php_out.read_bytes()
    # the intermediate via the /tmp eval-loader harness (the ic_lift pattern)
    from ioncube_re.container import decrypt_file

    dr = decrypt_file(f"{WORK}/marker81.php")
    off, end = dr["stream_region"]
    raw = dr["payload"][off:end]
    harness = php_intermediate_harness(str(tmp_path))
    rawf = tmp_path / "region.bin"
    rawf.write_bytes(raw)
    inter_f = tmp_path / "php_inter.bin"
    proc = subprocess.run(
        ["php", harness, str(rawf), hex(r["seed"]), str(inter_f)],
        capture_output=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert r["inter"] == inter_f.read_bytes(), "frame-codec intermediate not byte-exact"
    assert f"inter={len(r['inter'])}".encode() in proc.stdout


_PROD_FILES = [
    "cron.php",
    "admin/index.php",
    "library/front.php",
    "modules/billing/models/TaxGateway.php",
]


@requires_workspace
@requires_php
@pytest.mark.parametrize("rel", _PROD_FILES)
def test_prod_byte_exact_vs_php_oracle(tmp_path, rel):
    """prod: all 3 chunks' stream/cc/cplain artifacts byte-exact vs PHP."""
    f = os.path.join(CE, rel)
    php_prefix = tmp_path / "php" / "x"
    (tmp_path / "php").mkdir(exist_ok=True)
    rc, out, err = run_php(
        ["legacy-php/ic_stream.php", "prod", f, "--out", str(php_prefix)]
    )
    assert rc == 0, err
    r = prod_decode_file(f)
    assert len(r["chunks"]) == 3
    for c in r["chunks"]:
        n = c["num"]
        assert c["stream"] == (tmp_path / "php" / f"x.c{n}.stream.bin").read_bytes()
        assert c["blob"] == (tmp_path / "php" / f"x.c{n}.cc.bin").read_bytes()
        assert c["plain"] == (tmp_path / "php" / f"x.c{n}.cplain.bin").read_bytes()


@requires_workspace
@requires_php
def test_prod_intermediates_byte_exact_vs_php(tmp_path):
    """The frame-codec intermediates of a production chunk, via the /tmp harness."""
    f = os.path.join(CE, "cron.php")
    fields, chunks = prod_chunks(f)
    harness = php_intermediate_harness(str(tmp_path))
    r = prod_decode_file(f)
    for c in r["chunks"]:
        cont = prod_container(chunks[c["num"] - 1], f"chunk{c['num']}")
        raw = chunks[c["num"] - 1][cont["region_off"]:]
        rawf = tmp_path / f"raw_c{c['num']}.bin"
        rawf.write_bytes(raw)
        inter_f = tmp_path / f"php_inter_c{c['num']}.bin"
        proc = subprocess.run(
            ["php", harness, str(rawf), hex(cont["stream_seed"]), str(inter_f)],
            capture_output=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        assert c["inter"] == inter_f.read_bytes(), f"chunk{c['num']} intermediate"


@requires_workspace
@requires_php
def test_blesta_stream_byte_exact_vs_php(tmp_path):
    """1 blesta file: the stream layer byte-exact vs the PHP oracle."""
    f = os.path.join(WORK, "corpus", "blesta", "blesta", "app", "models", "license.php")
    (tmp_path / "php").mkdir(exist_ok=True)
    rc, out, err = run_php(["legacy-php/ic_stream.php", "prod", f, "--out", str(tmp_path / "php" / "x")])
    assert rc == 0, err
    r = prod_decode_file(f)
    for c in r["chunks"]:
        n = c["num"]
        assert c["stream"] == (tmp_path / "php" / f"x.c{n}.stream.bin").read_bytes()
        assert c["blob"] == (tmp_path / "php" / f"x.c{n}.cc.bin").read_bytes()
        assert c["plain"] == (tmp_path / "php" / f"x.c{n}.cplain.bin").read_bytes()


@requires_workspace
@requires_php
def test_cli_stream_verify_exit_code():
    """`ioncube-re stream verify` mirrors `ic_stream --verify` (exit 0, byte-exact)."""
    proc = cli(["stream", "verify", f"{WORK}/marker81.php",
                f"{M4}/marker81/readerA_*"])
    assert proc.returncode == 0, proc.stderr
    assert b"1007/1007 bytes MATCH" in proc.stdout
    rc, out, err = run_php(
        ["legacy-php/ic_stream.php", "--verify", "work/marker81.php",
         "work/dumps/m4/marker81/readerA_*"]
    )
    assert rc == 0
    assert b"1007/1007 bytes MATCH" in out


@pytest.mark.slow
@requires_workspace
def test_full_corpus_cli_sweep_461():
    """The CLI chain over every encoded corpus file, exit 0 each (the PHP
    tools' sweep, Python edition): 455 CE + 6 blesta."""
    ce_files = ce_encoded_files(CE)
    blesta_files = ce_encoded_files(os.path.join(WORK, "corpus", "blesta", "blesta"))
    assert len(ce_files) == 455
    assert len(blesta_files) == 6
    for f in ce_files + blesta_files:
        proc = cli(["stream", "prod", f], timeout=600)
        assert proc.returncode == 0, f"{f}: exit {proc.returncode}\n{proc.stderr[-500:]}"


@requires_workspace
@requires_php
def test_cli_decrypt_key_and_verify_parity():
    """`ioncube-re key` / `decrypt --verify` output mirrors ic_decrypt.php."""
    from conftest import cli

    rc_php, php_out, _ = run_php(["legacy-php/ic_decrypt.php", "key", "work/marker81.php"])
    assert rc_php == 0
    proc = cli(["key", f"{WORK}/marker81.php"])
    assert proc.returncode == 0
    assert proc.stdout == php_out, "key output differs from the PHP oracle"
    proc = cli(["decrypt", "--verify", f"{WORK}/marker81.php",
                f"{M4}/marker81/plain_0001_0x7fd19627c3c0_188B.bin"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith(b"VERIFY marker81.php: 172/172 bytes MATCH (dump ")
    rc_php, php_out, _ = run_php(
        ["legacy-php/ic_decrypt.php", "--verify", "work/marker81.php",
         "work/dumps/m4/marker81/plain_0001_0x7fd19627c3c0_188B.bin"]
    )
    assert rc_php == 0
    # identical modulo the dump path (the CLI was invoked with an absolute one)
    assert php_out.split(b"(dump ")[0] == proc.stdout.split(b"(dump ")[0]
