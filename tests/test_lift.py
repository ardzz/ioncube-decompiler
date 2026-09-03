"""Lifter tests: the two benchmark-gap closures + the 11-component gt table.

1. marker81 == semantic match to work/marker.php: the typed signature
   `function hello(string $who): string` (arg_info — benchmark gap #2), the
   CONCAT body without defensive parens, and the call;
2. cron.php statements match decodephp's §9.3 output statement-for-statement
   (interned-name resolution — benchmark gap #1);
3. the 11-component gt table reproduces the M6 §4 / M5C §3.2 numbers;
4. graceful degradation: unresolved interned entries keep placeholders,
   Blesta's wire-only fallback emits the class skeleton + method names;
5. CLI parity: `ioncube-re lift` exits 0 and carries the same output.
"""

import pytest
import re

from ioncube_re.lift import lift_file

from conftest import CE, M5, WORK, requires_workspace

# internal-field / quoted-superglobal artifact patterns, source positions
_ARTIFACT_RE = re.compile(r"->\d{8,}")
_QUOTED_SG_RE = re.compile(
    r"[(=\s!,]'(_GET|_POST|_REQUEST|_SERVER|_COOKIE|_SESSION|_FILES|_ENV)'"
)


def _strip_php_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


@requires_workspace
def test_marker81_semantic_match():
    """GT: work/marker.php = hello(string $who): string { return "hi " . $who; }
    echo hello("AAAA_marker_0001");  (notes/BENCHMARK-DECODEPHP.md §3)."""
    r = lift_file(f"{WORK}/marker81.php", m5dir=M5)
    t = r["text"]
    assert "function hello(string $who): string {" in t
    assert "return 'hi ' . $who;" in t
    assert "return ('hi ' . $who);" not in t  # no defensive CONCAT parens
    assert "echo hello('AAAA_marker_0001');" in t
    assert "0 masked" in t  # the arena path resolved the wD0 CONCAT node


@requires_workspace
def test_marker81_without_captures_still_sig_gates():
    """--no-auto equivalent (no m5 dir): the offline ktab lifts the sig-valid
    subset; hello's wD0 CONCAT degrades to an honest masked placeholder."""
    r = lift_file(f"{WORK}/marker81.php", m5dir=None)
    t = r["text"]
    assert "function hello(string $who): string {" in t
    assert "opcode masked" in t
    assert "op1=string('hi ')" in t


@requires_workspace
def test_lift_cli_marker81_m5_auto_discovery():
    """The CLI repro: `ioncube-re lift marker81.php` with no --m5-dir picks up
    the PHP tool's default m5 root (the __DIR__/../work/dumps/m5 equivalent) —
    hello() renders the CONCAT, not an opcode-masked $T1 placeholder."""
    from conftest import cli

    proc = cli(["lift", f"{WORK}/marker81.php"])
    assert proc.returncode == 0, proc.stderr
    text = proc.stdout.decode()
    assert "m5 capture match: marker81" in proc.stderr.decode()
    assert "return 'hi ' . $who;" in text
    assert "opcode masked" not in text


@requires_workspace
def test_blesta_license_chunk2_source_strings():
    """license.php chunk 2 source contract (work/dumps/m6-subwire/
    license_lift_chunk2.txt): the collector argument walk plus the +4
    VAR-read normalization render the CONCAT chain, the hash_file call and
    the new ReflectionClass; FETCH_CONSTANT renders bare (no \\' double-escape
    — a literal backslash before an opening quote)."""
    r = lift_file(f"{WORK}/corpus/blesta/blesta/app/models/license.php", chunk=2)
    t = r["text"]
    assert "hash_file(" in t
    assert "$V30" not in t and "$V42" not in t  # the +4 VAR-read leaks
    assert "new ReflectionClass($class)" in t
    assert "VENDORDIR . 'phpseclib' . " in t  # the CONCAT chain folds
    assert " \\'" not in t  # the double-escape; real escaped quotes are letter-adjacent


@requires_workspace
def test_cron_matches_decodephp_9_3():
    """The 6 statements of decodephp's cron.php preview, verbatim (§9.1)."""
    r = lift_file(f"{CE}/cron.php")
    lines = [l.strip() for l in r["text"].split("\n")]
    expected = [
        "$_GET['controller'] = 'index';",
        "$_GET['fuse'] = 'admin';",
        "$_GET['action'] = 'executeservice';",
        "define('RUNNING_SERVICE_SCRIPT', true);",
        "chdir(dirname(__FILE__));",
        "require 'library/front.php';",
    ]
    for stmt in expected:
        assert stmt in lines, f"missing statement: {stmt}"
    assert "/*interned-8 len=4*/" not in r["text"]  # every proven index resolved


@requires_workspace
def test_interned_resolution_honest():
    """The full interned table resolves the corpus indices (is_dir, log);
    out-of-range indices keep the placeholder — never a guess."""
    from ioncube_re.interned import interned_name, render_placeholder

    r = lift_file(f"{CE}/modules/billing/models/TaxGateway.php")
    assert "is_dir(" in r["text"]  # interned-249 len=6 (was a placeholder)
    assert "::log(" in r["text"]  # interned-284 len=3
    assert "/*interned-" not in r["text"]  # every corpus index resolves
    assert interned_name(599, 4) is None  # beyond the 591-entry table
    assert render_placeholder(599, 4) == "/*interned-599 len=4*/"
    assert interned_name(8, 6) is None  # length mismatch: never a guess


# (source, gt dump, [(section, ok/ok)]) — the M5C §3.2 numbers
_GT_CASES = [
    ("marker81.php", "gt_marker.txt", [("$_main:", "5/5"), ("hello:", "3/3")]),
    ("fresh81.php", "gt_fresh_src.txt", [("$_main:", "5/5"), ("Greeter::hi:", "3/3")]),
    ("gt_diverse1_81.php", "gt_gt_diverse1.txt", [("$_main:", "21/21")]),
    ("gt_diverse2_81.php", "gt_gt_diverse2.txt", [("$_main:", "39/39"), ("join2:", "5/5")]),
    ("gt_diverse3_81.php", "gt_gt_diverse3.txt",
     [("$_main:", "14/14"), ("Animal::label:", "2/2"),
      ("Dog::__construct:", "4/4"), ("Dog::label:", "4/4")]),
]


@requires_workspace
@pytest.mark.parametrize("src,gtfile,expect", _GT_CASES, ids=[c[0] for c in _GT_CASES])
def test_gt_table_via_lift(src, gtfile, expect):
    """The 11-component gt table through the lifter (the M5C §3.2 numbers)."""
    r = lift_file(f"{WORK}/{src}", gt=f"{M5}/{gtfile}", m5dir=M5)
    joined = "\n".join(r["gt"])
    assert "MISS" not in joined
    for sec, ok in expect:
        assert f"gt {sec}" in joined and f"opcode match {ok} gt oplines" in joined, \
            f"{src}: expected gt {sec} {ok} in:\n{joined}"


@requires_workspace
def test_blesta_lift():
    """Blesta lifts with the offline ktab since the M6-SUBWIRE str_len rule
    (mainblob ierg at 0x14+str_len; the Blesta generation carries +0x10):
    class skeleton + method names + try/catch, 0 masked nodes. (The +4/+2
    VAR-read normalizations of M6-SUBWIRE §7.4-5 are still unported — some
    call temps stay $Vn; PYTHON-PORT.md §4.2's remaining half.)"""
    r = lift_file(f"{WORK}/corpus/blesta/blesta/app/models/license.php")
    t = r["text"]
    assert t.count("// ===== component:") == 17
    assert "class Blesta\\App\\Models\\License extends Blesta\\App\\AppModel {" in t
    for m in ("load", "setKeys", "unload", "validate", "verify",
              "getLicenseData", "getStatistics"):
        assert f"function {m}(" in t
    assert "opcode masked" not in t  # offline-ktab resolves every component
    assert "try {" in t and "catch (Throwable" in t


@requires_workspace
def test_lift_cli_exit_zero():
    from conftest import cli

    proc = cli(["lift", f"{CE}/cron.php"])
    assert proc.returncode == 0, proc.stderr
    text = proc.stdout.decode()
    assert "$_GET['controller'] = 'index';" in text
    assert b"\xe2\x80\x94" in proc.stdout  # the em-dash header line (UTF-8)


@requires_workspace
def test_superglobal_isset_ternary_repro():
    """The LINT-GATE repro (AnnouncementsController getannouncementsAction):
    FETCH_IS of a superglobal name renders `$_REQUEST` (never a quoted
    constant / an internal-field leak), and the isset-guard ternary emits
    its branch content instead of empty if/else shells."""
    r = lift_file(f"{CE}/modules/admin/controllers/AnnouncementsController.php",
                  chunk=1)
    t = r["text"]
    assert "$limit = (isset($_REQUEST['limit']) ? $_REQUEST['limit'] : 25);" in t
    assert "$start = (isset($_REQUEST['start']) ? $_REQUEST['start'] : 0);" in t
    assert "$sort = (isset($_REQUEST['sort']) ? $_REQUEST['sort'] : 'id');" in t
    assert "$dir = (isset($_REQUEST['dir']) ? $_REQUEST['dir'] : 'desc');" in t
    assert "isset($_REQUEST['limit'])" in t  # not '_REQUEST'-quoted


@requires_workspace
def test_no_operand_leak_artifacts():
    """Zero internal-field artifacts in SOURCE positions: the 0xFFFFFFFF
    unused marker never renders after `->` (4294967295 remains legal as an
    integer literal — ClientExec uses it as a sentinel), superglobals never
    render as quoted constants. Action.php was the artifact-heaviest file;
    upload.class.php carries the call-arm ternaries; masked-node diagnostic
    comments are excluded (comment-stripped text)."""
    for f in ("library/CE/Controller/Action.php",
              "modules/files/models/upload.class.php",
              "modules/admin/controllers/AnnouncementsController.php"):
        t = _strip_php_comments(lift_file(f"{CE}/{f}", chunk=1)["text"])
        assert not _ARTIFACT_RE.search(t), f
        assert not _QUOTED_SG_RE.search(t), f


@requires_workspace
def test_corpus_zero_artifact_patterns():
    """Corpus-wide: no `->NNNNNNNN` internal-field leaks and no
    quoted-superglobal operands in any of the CE chunk-1 lifts (source
    positions only — masked-node diagnostic comments are stripped)."""
    from conftest import ce_encoded_files

    for f in ce_encoded_files(CE):
        t = _strip_php_comments(lift_file(f, chunk=1)["text"])
        assert not _ARTIFACT_RE.search(t), f
        assert not _QUOTED_SG_RE.search(t), f


@requires_workspace
def test_call_arm_ternary_corpus():
    """upload.class.php get_version_param: a call chain in the ternary arm
    folds (the arms are expression regions, calls included)."""
    t = lift_file(f"{CE}/modules/files/models/upload.class.php", chunk=1)["text"]
    assert ("return isset($_GET['version']) ? "
            "basename(stripslashes($_GET['version'])) : null;") in t


@requires_workspace
def test_superglobal_empty_var_name():
    """`empty($_POST)` lowers to ISSET_ISEMPTY_VAR with op1 = the NAME zval
    (TicketController addreplyticketAction) — the name renders as the
    superglobal, and the && chain merges into one condition."""
    t = lift_file(f"{CE}/modules/support/controllers/TicketController.php",
                  chunk=1)["text"]
    assert "empty($_POST)" in t
    assert "empty('_POST')" not in t
    assert "empty(/*interned" not in t
