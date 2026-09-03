"""The php -l gate (notes/LINT-GATE.md): docker-exec lint of lift output,
the exit-3 failure contract, --lint/--no-lint flags, and the pure-Python
degraded engine used when the php81-test container is unavailable."""

import pytest

from ioncube_re.cli import build_parser
from ioncube_re.lint import LINT_FAIL, php_lint

from conftest import WORK, requires_workspace


def _container_up():
    from ioncube_re.lint import container_up

    return container_up()


requires_container = pytest.mark.skipif(
    not _container_up(), reason="php81-test container not available"
)


def _cli(args):
    from conftest import cli

    return cli(args)


@requires_workspace
@requires_container
def test_lint_ok_marker81():
    """The acceptance contract: `ioncube-re lift work/marker81.php` ends
    with LINT: OK and exits 0."""
    proc = _cli(["lift", f"{WORK}/marker81.php"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.decode().rstrip().endswith("LINT: OK")


@requires_workspace
@requires_container
def test_lint_fail_exit_3():
    """A parse failure is the FINAL output line with the verbatim php -l
    error and line number, and the exit code is 3 (license.php's namespaced
    class declaration — the documented pre-existing lint failure)."""
    proc = _cli(["lift", "--chunk", "1",
                 f"{WORK}/corpus/blesta/blesta/app/models/license.php"])
    assert proc.returncode == LINT_FAIL
    last = proc.stdout.decode().rstrip().splitlines()[-1]
    assert last.startswith("LINT: FAIL (line 8: syntax error, unexpected "
                           'namespaced name "Blesta\\App\\Models\\License"')


@requires_workspace
def test_no_lint_flag_disables_gate():
    """--no-lint: no LINT line at all, exit 0 even on the file that fails
    php -l with the gate on."""
    proc = _cli(["lift", "--no-lint", "--chunk", "1",
                 f"{WORK}/corpus/blesta/blesta/app/models/license.php"])
    assert proc.returncode == 0
    assert "LINT:" not in proc.stdout.decode()


def test_lint_flags_default_on():
    """--lint is the default; --no-lint disables (the operator's gate is
    permanent unless explicitly waived)."""
    a = build_parser().parse_args(["lift", "x.php"])
    assert a.lint is True
    a = build_parser().parse_args(["lift", "x.php", "--no-lint"])
    assert a.lint is False
    a = build_parser().parse_args(["lift", "x.php", "--lint"])
    assert a.lint is True


def test_degraded_lint_balanced(monkeypatch):
    monkeypatch.setattr("ioncube_re.lint.container_up", lambda: False)
    line, ok = php_lint("<?php\n$x = (isset($_GET['k']) ? 1 : 2);\necho $x;\n")
    assert ok
    assert line.startswith("LINT: OK (degraded lint")


def test_degraded_lint_artifact(monkeypatch):
    """An internal-field leak fails even the degraded engine (the
    `->NNNNNNNN` family can never be valid PHP)."""
    monkeypatch.setattr("ioncube_re.lint.container_up", lambda: False)
    line, ok = php_lint("<?php\nif (isset($_REQUEST->4294967295['limit'])) {\n}\n")
    assert not ok
    assert "LINT: FAIL (line 2: internal field in output" in line
    assert "degraded lint" in line


def test_degraded_lint_unbalanced(monkeypatch):
    monkeypatch.setattr("ioncube_re.lint.container_up", lambda: False)
    line, ok = php_lint("<?php\nif (isset($_GET['k'])) {\necho 1;\n")
    assert not ok
    assert "unclosed" in line or "unbalanced" in line


def test_degraded_lint_skips_comments_and_strings(monkeypatch):
    """Comment/string contents must not count toward bracket balance —
    the lift output is comment-heavy by design."""
    monkeypatch.setattr("ioncube_re.lint.container_up", lambda: False)
    line, ok = php_lint(
        "<?php\n// if (x { { {\n"
        "/* } } } ( ( ( */\n"
        "$s = 'if ( { [ (';\n"
        "if (isset($_GET['k'])) {\n    $x = [1, 2];\n}\n"
    )
    assert ok, line
