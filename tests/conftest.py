"""Shared fixtures: research-workspace paths, ground-truth files, oracle helpers.

The corpus and dumps are NEVER bundled into this project — they are referenced
by path into the (frozen, read-only) research workspace
/home/reky/workspaces/cylab/ioncube. Every test that needs them skips
gracefully when the workspace is absent, so `uv run pytest` works standalone.
"""

import hashlib
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE = os.environ.get(
    "IONCUBE_RE_WORKSPACE", "/home/reky/workspaces/cylab/ioncube"
)
WORK = os.path.join(WORKSPACE, "work")
M4 = os.path.join(WORK, "dumps", "m4")
M5 = os.path.join(WORK, "dumps", "m5")
M6 = os.path.join(WORK, "dumps", "m6")
M6KT = os.path.join(WORK, "dumps", "m6-keytab")
CORPUS = os.path.join(WORK, "corpus")
CE = os.path.join(CORPUS, "clientexec", "clientexec")
BLESTA = os.path.join(CORPUS, "blesta", "blesta")

# the analyzed loader build (notes/M6-OPERANDS.md, M4): 15.5.0, PHP 8.1
LOADER_SHA256 = "380f2ecad4ba295f66ebd88a758b55a75fc567b17b852e95f4788b0b588ebf98"
LOADER = os.path.join(WORKSPACE, "loaders", "ioncube_loader_lin_8.1.so")


def workspace_available() -> bool:
    return os.path.isdir(M5)


def php_available() -> bool:
    return shutil.which("php") is not None


requires_workspace = pytest.mark.skipif(
    not workspace_available(), reason="research workspace not available"
)
requires_php = pytest.mark.skipif(
    not php_available(), reason="php CLI not available for the frozen oracles"
)


@pytest.fixture(scope="session")
def workspace():
    if not workspace_available():
        pytest.skip("research workspace not available")
    return WORKSPACE


@pytest.fixture(scope="session")
def m4():
    if not workspace_available():
        pytest.skip("research workspace not available")
    return M4


@pytest.fixture(scope="session")
def m5():
    if not workspace_available():
        pytest.skip("research workspace not available")
    return M5


@pytest.fixture(scope="session")
def corpus_ce():
    if not os.path.isdir(CE):
        pytest.skip("clientexec corpus not available")
    return CE


@pytest.fixture(scope="session")
def corpus_blesta():
    if not os.path.isdir(BLESTA):
        pytest.skip("blesta corpus not available")
    return BLESTA


def run_php(args, cwd=WORKSPACE, timeout=300):
    """Run a frozen PHP oracle; returns (exit code, stdout bytes, stderr bytes)."""
    proc = subprocess.run(
        ["php"] + args, cwd=cwd, capture_output=True, timeout=timeout
    )
    return proc.returncode, proc.stdout, proc.stderr


def php_intermediate_harness(tmpdir) -> str:
    """Write (and return) the /tmp PHP harness that loads ic_stream.php's
    library body (the ic_lift loader pattern: eval up to the CLI marker) and
    dumps frame_decode's intermediate — the byte-exact intermediate oracle.

    The eval'd body resolves its ic_decrypt.php dependency through __DIR__,
    so a read-only copy of that file is placed next to the harness. Everything
    lives OUTSIDE the frozen workspace; nothing there is modified."""
    os.makedirs(tmpdir, exist_ok=True)
    shutil.copy(os.path.join(WORKSPACE, "legacy-php", "ic_decrypt.php"),
                os.path.join(tmpdir, "ic_decrypt.php"))
    path = os.path.join(tmpdir, "oracle_inter.php")
    with open(path, "w") as f:
        f.write(
            "<?php\n"
            f"$src = file_get_contents({WORKSPACE!r} . '/legacy-php/ic_stream.php');\n"
            "$cut = strrpos($src, '// ---------- CLI ----------');\n"
            "$body = substr($src, 0, $cut);\n"
            'foreach (["#!/usr/bin/env php\\n", "<?php\\n", "<?php"] as $pre)\n'
            "    while (strpos($body, $pre) === 0) $body = substr($body, strlen($pre));\n"
            "eval($body . \"\\n\");\n"
            "$raw = file_get_contents($argv[1]);\n"
            "list($inter, $frames, $ck, $ad) = frame_decode($raw, hexdec($argv[2]));\n"
            "file_put_contents($argv[3], $inter);\n"
            "printf(\"frames=%d ckpts=%d adler=%08x inter=%d\\n\", $frames, $ck, $ad, strlen($inter));\n"
        )
    return path


def sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def ce_encoded_files(root: str) -> list[str]:
    """The ionCube-encoded subset of a corpus tree (the ICB0 prologue)."""
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith(".php"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "rb") as f:
                    if f.read(12) == b"<?php //ICB0":
                        out.append(p)
            except OSError:
                pass
    return sorted(out)


def cli(args, timeout=300) -> subprocess.CompletedProcess:
    """Run the project's own CLI (python -m ioncube_re) — the real surface."""
    return subprocess.run(
        [sys.executable, "-m", "ioncube_re"] + args,
        capture_output=True, timeout=timeout, cwd=REPO,
    )
