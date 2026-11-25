"""Extract the keytable mask of a license-bound (dynamic-key) encoded file.

A dynamic-key file stores a decoy mask in its main blob.  The real mask is
derived by the ionCube Loader from the license's hidden ``__mykey`` property:
the loader decodes the property to a decimal value ``K`` and computes
``mask = K // 7 - 13`` (verified against ionCube Loader 13.0.2 for PHP 8.2).

The property itself is inside ionCube's encrypted license payload, so the
loader is needed to decrypt it.  This module runs a minimal PHP harness that
includes the encoded file under the installed loader and reads the final mask
from the loader's memory (the loader keeps it in its .bss while the file is
loaded).

WARNING: this executes the encoded file's top-level code through the loader
(the vendor file is not otherwise called).  Only run it on files you trust,
and only on a machine with a valid license.  The loader build is checked:
this knows the ionCube Loader 13.0.2 / PHP 8.2 layout
(``ioncube_loader_lin_8.2.so``, 1439016 bytes, key global at
``base + 0x2608C0``).  Other builds raise :class:`LicenseKeyError` instead of
returning a wrong value, and older-format files that the loader itself
rejects (e.g. PHP 7.2 builds) cannot be handled this way.
"""

from __future__ import annotations

import os
import select
import subprocess
import tempfile
import time

LOADER_SUFFIX = "ioncube_loader_lin_8.2.so"
LOADER_SIZE = 1439016
KEY_GLOBAL_OFF = 0x2608C0

# __mykey wire decoding (see the license-payload format):
# [marker byte][u16 length ^ LENGTH_XOR][payload ^ NAMEKEY bytes, repeating]
NAMEKEY = 0xE9FC23B1
LENGTH_XOR = 0x23B1

# The loader's post-processing of the decoded decimal value.
MASK_DIVISOR = 7
MASK_OFFSET = 13


class LicenseKeyError(Exception):
    """The mask could not be extracted (no loader, bad build, file rejected)."""


def decode_mykey(raw: bytes) -> int:
    """Decode one hidden ``__mykey`` license property value to its integer.

    ``raw`` is the value as returned by the loader's internal property
    lookup (not the license text): a marker byte, a little-endian u16 length
    XORed with 0x23B1, then that many bytes XORed with the repeating namekey
    bytes (``b1 23 fc e9``).  The result is a decimal string.
    """
    if len(raw) < 3:
        raise LicenseKeyError("__mykey value is too short")
    ln = int.from_bytes(raw[1:3], "little") ^ LENGTH_XOR
    if ln < 1 or 3 + ln > len(raw):
        raise LicenseKeyError(f"__mykey length {ln} is out of range")
    key = NAMEKEY.to_bytes(4, "little")
    text = bytes(b ^ key[i % 4] for i, b in enumerate(raw[3 : 3 + ln]))
    try:
        return int(text.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as e:
        raise LicenseKeyError(f"__mykey is not a decimal string: {text!r}") from e


def mask_from_mykey(raw: bytes) -> int:
    """The loader's mask derivation from a raw ``__mykey`` value.

    Verified for the 13.0.2 / PHP 8.2 loader.  This is informative; the
    extractor below reads the loader's final value instead of relying on
    the formula.
    """
    return (decode_mykey(raw) // MASK_DIVISOR - MASK_OFFSET) & 0xFFFFFFFF


def _loader_mapping(pid: int) -> tuple[int, str] | None:
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                if LOADER_SUFFIX in line and "r-xp" in line:
                    parts = line.split()
                    start = int(parts[0].split("-", 1)[0], 16)
                    return start, parts[-1]
    except OSError:
        return None
    return None


def _read_u32(pid: int, addr: int) -> int | None:
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
            f.seek(addr)
            b = f.read(4)
            return int.from_bytes(b, "little") if len(b) == 4 else None
    except OSError:
        return None


def _php_quote(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _stderr_tail(proc: subprocess.Popen) -> str:
    """Stop a failed child and return its last stderr line (if any)."""
    try:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if proc.stderr is not None:
            err = proc.stderr.read() or ""
        else:
            err = ""
    except (OSError, ValueError):
        return ""
    lines = [ln.strip() for ln in err.strip().splitlines() if ln.strip()]
    for ln in lines:
        low = ln.lower()
        if "error" in low or "cannot be decoded" in low:
            return ln
    return lines[0] if lines else ""


def extract_license_key(
    encoded: str, php: str = "php", timeout: float = 20.0
) -> int:
    """Return the loader's effective keytable mask for ``encoded``.

    Runs ``php`` on a temporary harness that includes ``encoded``, waits for
    the loader to finish, then reads the mask from the loader's .bss.
    The encoded file's top-level executes (see the module warning).
    """
    if not os.path.isfile(encoded):
        raise LicenseKeyError(f"not a file: {encoded}")
    fd, harness = tempfile.mkstemp(suffix=".php", prefix="ioncubekey-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(
                "<?php\n"
                f"include {_php_quote(os.path.abspath(encoded))};\n"
                'echo "READY\\n";\n'
                "sleep(30);\n"
            )
        proc = subprocess.Popen(
            [php, harness],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    err = _stderr_tail(proc)
                    raise LicenseKeyError(
                        "timed out waiting for the loader"
                        + (f": {err}" if err else "")
                    )
                ready, _, _ = select.select([proc.stdout], [], [], remaining)
                if not ready:
                    err = _stderr_tail(proc)
                    raise LicenseKeyError(
                        "timed out waiting for the loader"
                        + (f": {err}" if err else "")
                    )
                line = proc.stdout.readline()
                if not line:
                    err = _stderr_tail(proc)
                    raise LicenseKeyError(
                        "encoded file did not load (license/loader problem)"
                        + (f": {err}" if err else "")
                    )
                if line.strip() != "READY":
                    continue
                mapped = _loader_mapping(proc.pid)
                if mapped is None:
                    raise LicenseKeyError("ionCube Loader is not loaded")
                base, loader_path = mapped
                try:
                    size = os.path.getsize(loader_path)
                except OSError:
                    size = -1
                if size != LOADER_SIZE:
                    raise LicenseKeyError(
                        f"unsupported loader build {loader_path!r} "
                        f"({size} bytes; this tool knows ionCube Loader "
                        f"13.0.2 / PHP 8.2)"
                    )
                mask = _read_u32(proc.pid, base + KEY_GLOBAL_OFF)
                if mask is None:
                    raise LicenseKeyError("cannot read the loader's key global")
                return mask
        finally:
            proc.kill()
            proc.wait()
    finally:
        try:
            os.unlink(harness)
        except OSError:
            pass


__all__ = [
    "LicenseKeyError",
    "decode_mykey",
    "mask_from_mykey",
    "extract_license_key",
]
