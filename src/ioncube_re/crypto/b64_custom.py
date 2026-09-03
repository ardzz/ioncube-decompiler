"""Custom base64 codec (loader 0x42303).

Alphabet "0-9A-Za-z+/" (digits before letters — NOT the RFC 4648 order),
6-bit accumulator, '=' skipped. Lines are taken after the `?>` close-tag
line, whitespace-stripped. Byte-exact port of ic_decrypt.php payload_of().
"""

import base64
import re

ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
_MAP = {c: i for i, c in enumerate(ALPHA)}
# custom alphabet -> standard RFC 4648 alphabet (same 6-bit packing, C-speed)
_TO_STD = bytes.maketrans(
    ALPHA.encode("ascii"),
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".encode("ascii"),
)
_B64_RUN = re.compile(rb"[0-9A-Za-z+/=]+")


def b64_decode(text: str) -> bytes:
    """Decode custom-base64 `text` (a str of ASCII chars). Raises on bad chars."""
    out = bytearray()
    acc = 0
    bits = 0
    for ch in text:
        if ch == "=":
            continue
        v = _MAP.get(ch)
        if v is None:
            raise ValueError(f"bad base64 char {ch!r}")
        acc = (acc << 6) | v
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


def payload_of(data: bytes) -> bytes:
    """Extract the payload: custom-b64 lines after the `?>` line, whitespace removed."""
    lines = data.split(b"\n")
    pl = []
    after = False
    for ln in lines:
        if not after:
            if ln.rstrip() == b"?>":
                after = True
            continue
        t = ln.rstrip()
        if t:
            pl.append(t)
    if not after:
        raise ValueError("no ?> line found")
    if not pl:
        raise ValueError("no payload lines after ?>")
    text = b"".join(pl).decode("ascii").strip()
    # PHP collapses ALL whitespace runs: preg_replace('/\s+/', '', ...)
    text = "".join(text.split())
    out = b64_decode(text)
    if not out:
        raise ValueError("empty payload")
    return out


def chunk_split(data: bytes) -> list[bytes]:
    """Split an ICB0 production payload region into '='-separated chunks.

    The loader's base64 decoder stops at the first '=' (that is the chunk
    separator); each chunk decodes independently. Port of prod_chunks() tail
    (ic_stream.php): skip CR/LF, flush at '=' runs, stop at the first
    non-alphabet byte.

    Fast path: the custom alphabet is a permutation of the standard one with
    identical 6-bit packing (4 chars -> 3 bytes, unpadded leftovers 2 -> 1 /
    3 -> 2 — exactly the PHP accumulator's behavior), so each chunk decodes
    via translate + base64.b64decode.
    """
    text = data.translate(None, b"\r\n")
    m = _B64_RUN.match(text)
    if m is None:
        return []
    chunks = []
    for piece in m.group().split(b"="):
        if not piece:
            continue
        std = piece.translate(_TO_STD)
        r = len(std) % 4
        if r == 1:
            chunks.append(b"")  # 6 bits — no full byte (the PHP accumulator emits none)
        else:
            chunks.append(base64.b64decode(std + b"=" * ((4 - r) % 4), validate=True))
    return chunks
