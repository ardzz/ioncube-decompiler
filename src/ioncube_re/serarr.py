"""ionCube serialized constant-array decoder — the dawwinci grammar port.

ionCube compiles PHP array literals with all-constant values into a binary
format (a variant of PHP's serialize() output) and stores them in the wire
pool; zvals with type&0xff==7 carry the blob. The grammar (ported verbatim
in structure from dawwinci/ioncube-php8-decompiler
src/php_reconstructor/utils/php_values.py:70-221, MIT License, Copyright (c)
2026 dawwinci <goamcisa@gmail.com> — see notes/DAWWINCI-DIFF.md §1 row 1/§3
for the byte-level verification of this grammar on our corpora):

    array    = '[' entry* '}' trailer
    entry    = str_entry | int_entry
    str_entry= DIGITS "'" KEY_BYTES type_value metadata
    int_entry= DIGITS ":" DIGITS type_value [metadata]
    type_value:
      's' DIGITS "'" VALUE_BYTES   -> str (4 metadata fields)
      'i' DIGITS ";"               -> int (2 metadata fields)
      'd' DIGITS ";"               -> float (2 metadata fields)
      'b' DIGITS ";"               -> bool (2 metadata fields)
      '[' entry* '}' trailer       -> sub-array (0 extra metadata fields)
    trailer  = 5x (DIGITS ";")
    metadata = N x (DIGITS ";")     (N given by type_value; values are
                                     per-build hashes / type echoes — skipped)

Our byte-level additions beyond their doc (notes/SERARR-PORT.md §2):
  * production-generation pool blobs carry one leading 0x81 byte before the
    '[' (eval-generation blobs start at '[' directly) — skipped here;
  * empty arrays appear as type=007 (no refcounted bits) with the trailer
    `8;7;0;2;71;` — same 5-field shape, decodes to [].
"""

from __future__ import annotations


def _php_quote_str(s: str) -> str:
    """Single-quote a PHP string literal (the emitter's php_quote rules)."""
    if any(c in s for c in "\n\r\t"):
        t = s.replace("\\", "\\\\").replace('"', '\\"')
        t = t.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return f'"{t}"'
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


class _SerarrParser:
    __slots__ = ("_d", "_p")

    def __init__(self, data: bytes) -> None:
        self._d = data
        self._p = 0

    def _read_byte(self) -> int:
        b = self._d[self._p]
        self._p += 1
        return b

    def _expect(self, ch: str) -> None:
        b = self._read_byte()
        if b != ord(ch):
            raise ValueError(f"expected {ch!r}, got {chr(b)!r} at pos {self._p - 1}")

    def _read_digits(self) -> int:
        start = self._p
        while self._p < len(self._d) and 48 <= self._d[self._p] <= 57:
            self._p += 1
        if self._p == start:
            raise ValueError(f"expected digits at pos {self._p}")
        return int(self._d[start:self._p])

    def _read_until_semi(self) -> str:
        start = self._p
        while self._p < len(self._d) and self._d[self._p] != 59:
            self._p += 1
        if self._p >= len(self._d):
            raise ValueError(f"expected ';' at pos {self._p}")
        v = self._d[start:self._p].decode("ascii")
        self._p += 1
        return v

    def _skip_fields(self, n: int) -> None:
        for _ in range(n):
            self._read_until_semi()

    def _read_n_bytes(self, n: int) -> bytes:
        chunk = self._d[self._p:self._p + n]
        if len(chunk) < n:
            raise ValueError("truncated payload")
        self._p += n
        return chunk

    def read_array(self) -> list:
        self._expect("[")
        entries: list = []
        terminated = False
        while self._p < len(self._d):
            b = self._d[self._p]
            if b == 125:  # '}'
                self._p += 1
                self._skip_fields(5)  # fixed-size array trailer
                terminated = True
                break
            if 48 <= b <= 57:  # digit -> start of an entry
                entries.append(self._read_entry())
            else:
                raise ValueError(f"unexpected 0x{b:02x} in array at pos {self._p}")
        if not terminated:
            raise ValueError(f"unterminated array (no '}}' + trailer) at pos {self._p}")
        return entries

    def _read_entry(self) -> tuple:
        num = self._read_digits()
        nxt = self._d[self._p] if self._p < len(self._d) else 0

        if nxt == 58:  # ':' -> integer-keyed entry (the leading digits are
            # the key's digit length — ignored, the key follows the ':')
            self._p += 1
            key: int | str = self._read_digits()
        elif nxt == 39:  # "'" -> string-keyed entry (leading digits = key length)
            self._p += 1
            raw = self._read_n_bytes(num)
            try:
                key = raw.decode("utf-8")
            except UnicodeDecodeError:
                key = raw.decode("latin-1")
        else:
            raise ValueError(f"expected ':' or \"'\" after digits, got 0x{nxt:02x}")

        value, meta = self._read_typed_value()
        if meta:
            self._skip_fields(meta)
        return (key, value)

    def _read_typed_value(self) -> tuple:
        """Return (value, metadata_field_count)."""
        ch = chr(self._read_byte())

        if ch == "s":
            n = self._read_digits()
            self._expect("'")
            raw = self._read_n_bytes(n)
            try:
                return raw.decode("utf-8"), 4
            except UnicodeDecodeError:
                return raw.decode("latin-1"), 4
        if ch == "i":
            return int(self._read_until_semi()), 2
        if ch == "d":
            return float(self._read_until_semi()), 2
        if ch == "b":
            return bool(int(self._read_until_semi())), 2
        if ch == "[":
            self._p -= 1  # put '[' back; read_array() consumes it
            return self.read_array(), 0
        raise ValueError(f"unknown value type {ch!r} at pos {self._p - 1}")


def decode_serarr(data: bytes, exact: bool = False) -> list[tuple[int | str, object]] | None:
    """Parse an ionCube serialized-array blob into a list of (key, value)
    pairs (keys int/str; values int/float/str/bool or a nested pair list),
    or None if the data does not parse. `exact` additionally requires the
    whole blob to be consumed (the test-suite form)."""
    if data[:1] == b"\x81":  # production-generation pool prefix
        data = data[1:]
    if not data or data[0:1] != b"[":
        return None
    try:
        p = _SerarrParser(data)
        result = p.read_array()
        if exact and p._p != len(data):
            return None
        return result
    except (ValueError, IndexError):
        return None


def php_array_literal(pairs: list) -> str:
    """Render decoded pairs as a PHP array literal (['k' => v, ...]).
    Sequential int keys 0,1,2,... render implicitly (PHP source style),
    matching the emitter's collectArray convention."""
    if not pairs:
        return "[]"
    items = []
    for pos, (k, v) in enumerate(pairs):
        rendered = php_value(v)
        if isinstance(k, int) and k == pos:
            items.append(rendered)
        else:
            items.append(php_value(k) + " => " + rendered)
    return "[" + ", ".join(items) + "]"


def php_value(v: object) -> str:
    if isinstance(v, list):
        return php_array_literal(v)
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return _php_quote_str(v)
    return str(v)
