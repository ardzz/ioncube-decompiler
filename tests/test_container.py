"""Container-layer tests: the 3 regressions.

1. marker81 main-blob 172/172 vs the live gdb capture (plain_0001);
2. the full 455-file ClientExec corpus passes the offline production chain
   (ICB0 -> chunk split -> container adler -> frame codec -> deflate ->
   component blob + layer-B) — the M5-PROD sweep, Python edition;
3. the 6 Blesta files pass the same stream-layer chain.
"""

import os

from ioncube_re.container import decrypt_file, layer_a, prod_container, prod_chunks
from ioncube_re.stream import StreamError, prod_decode_file

from conftest import (
    BLESTA,
    CE,
    LOADER,
    LOADER_SHA256,
    M4,
    WORK,
    ce_encoded_files,
    requires_workspace,
)


@requires_workspace
def test_loader_pinned():
    """The reversed build: ionCube Loader 15.5.0 for PHP 8.1 (hash-pinned)."""
    assert os.path.isfile(LOADER)
    import hashlib

    h = hashlib.sha256(open(LOADER, "rb").read()).hexdigest()
    assert h == LOADER_SHA256


@requires_workspace
def test_marker81_main_blob_172():
    r = decrypt_file(f"{WORK}/marker81.php")
    import glob

    live = open(sorted(glob.glob(f"{M4}/marker81/plain_0001_*_188B.bin"))[0], "rb").read()
    assert r["ok"]  # adler + MD4 fold
    assert len(r["plain"]) == 172
    assert r["plain"] + r["cipher"][-16:] == live  # the in-place buffer, 172/172 + rol3 tail


@requires_workspace
def test_ce_corpus_455_chain():
    files = ce_encoded_files(CE)
    assert len(files) == 455, f"expected 455 encoded CE files, got {len(files)}"
    for f in files:
        r = prod_decode_file(f)
        assert r["chunks"], f
        for c in r["chunks"]:
            assert c["adler_ok"], f"{f} chunk{c['num']} adler"
            assert c["ckpts"] >= 1, f"{f} chunk{c['num']} checkpoints"
            assert "plain" in c, f"{f} chunk{c['num']}: component blob not found"


@requires_workspace
def test_blesta_6_chain():
    files = ce_encoded_files(BLESTA)
    assert len(files) == 6, f"expected 6 encoded blesta files, got {len(files)}"
    for f in files:
        r = prod_decode_file(f)
        assert len(r["chunks"]) == 3
        for c in r["chunks"]:
            assert c["adler_ok"], f"{f} chunk{c['num']} adler"
            assert "plain" in c, f"{f} chunk{c['num']} component blob"


def test_decrypt_rejects_non_container(tmp_path):
    import pytest

    junk = tmp_path / "junk.php"
    junk.write_bytes(b"<?php echo 'not ioncube';\n")
    with pytest.raises(ValueError):
        decrypt_file(str(junk))
