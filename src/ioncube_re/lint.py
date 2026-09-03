"""The php -l output gate (the operator's lint contract, notes/LINT-GATE.md).

Lift output must parse as PHP. The primary engine is the php81-test
container: the rendered listing is piped to ``docker exec -i php81-test
php -l`` (stdin, exactly the shell form
``echo "$OUT" | docker exec -i php81-test php -l``). When the container is
unavailable the gate degrades to a pure-Python check — bracket/quote
balance plus the internal-field artifact patterns — and says so; the gate
never silently widens.

Report contract (the CLI's FINAL output line):
  ``LINT: OK``                       — php -l found no syntax errors
  ``LINT: FAIL (line N: <php -l verbatim error>)`` — a parse error
The CLI exits 3 on lint failure (LINT_FAIL) so scripts can gate on it.
"""

from __future__ import annotations

import re
import shutil
import subprocess

CONTAINER = "php81-test"
LINT_FAIL = 3

# zval internal fields (0xFFFFFFFF unused markers, raw receiver values) —
# a bare numeric property after `->` can never be valid PHP source
_ARTIFACTS = re.compile(r"->\d{8,}")
# php -l on stdin always reports the file as "Standard input code"
_PHP_ERR = re.compile(
    r"^(?:PHP )?(?:Parse|Fatal) error:\s*(.*) in Standard input code on line (\d+)\s*$",
    re.MULTILINE,
)


def container_up() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(
            ["docker", "ps", "--filter", f"name={CONTAINER}", "--format",
             "{{.Names}}"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and CONTAINER in r.stdout.split()


def php_lint(text: str) -> tuple[str, bool]:
    """Lint one rendered listing. Returns (final report line, ok)."""
    if not container_up():
        return _degraded(text, "php81-test container unavailable")
    try:
        r = subprocess.run(
            ["docker", "exec", "-i", CONTAINER, "php", "-l"],
            input=text.encode("latin-1", "replace"),
            capture_output=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return _degraded(text, f"docker exec failed: {e}")
    if r.returncode in (125, 126, 127):  # docker-side failure, not php's
        return _degraded(text, f"docker exec rc={r.returncode}")
    out = (r.stdout + b"\n" + r.stderr).decode("latin-1", "replace")
    if r.returncode == 0 and "No syntax errors detected" in out:
        return "LINT: OK", True
    m = _PHP_ERR.search(out)
    if m:
        return f"LINT: FAIL (line {m.group(2)}: {m.group(1).strip()})", False
    first = out.strip().splitlines()[0] if out.strip() else "no output"
    return f"LINT: FAIL (php -l rc={r.returncode}: {first})", False


# ---- the pure-Python degraded engine ----

def _balance(text: str) -> tuple[int, str] | None:
    """First bracket/quote imbalance as (line, msg), or None when balanced.

    A hand-rolled scanner over code, skipping '...'/"..." strings (with
    escapes) and // # /* */ comments — heredocs are never emitted."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[tuple[str, int]] = []
    state = ""  # "", "'", '"', "//", "#", "/*"
    line = 1
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            if state in ("//", "#"):
                state = ""
            i += 1
            continue
        if state in ("'", '"'):
            if c == "\\":
                i += 2
                continue
            if c == state:
                state = ""
            i += 1
            continue
        if state == "/*":
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                state = ""
                i += 2
                continue
            i += 1
            continue
        if state in ("//", "#"):
            i += 1
            continue
        if c in ("'", '"'):
            state = c
        elif c == "#":
            state = "#"
        elif c == "/" and text[i + 1 : i + 2] == "/":
            state = "//"
        elif c == "/" and text[i + 1 : i + 2] == "*":
            state = "/*"
        elif c in "([{":
            stack.append((c, line))
        elif c in ")]}":
            if not stack or stack[-1][0] != pairs[c]:
                return line, f"unbalanced '{c}'"
            stack.pop()
        i += 1
    if state in ("'", '"'):
        return line, f"unterminated {state} string"
    if stack:
        return stack[-1][1], f"unclosed '{stack[-1][0]}'"
    return None


def _artifact(text: str) -> tuple[int, str] | None:
    for ln, line in enumerate(text.splitlines(), 1):
        m = _ARTIFACTS.search(line)
        if m:
            return ln, f"internal field in output: '{m.group(0)}'"
    return None


def _degraded(text: str, why: str) -> tuple[str, bool]:
    err = _artifact(text) or _balance(text)
    note = f" (degraded lint — {why}; balance + artifact checks only)"
    if err is not None:
        return f"LINT: FAIL (line {err[0]}: {err[1]}){note}", False
    return f"LINT: OK{note}", True


__all__ = ["LINT_FAIL", "container_up", "php_lint"]
