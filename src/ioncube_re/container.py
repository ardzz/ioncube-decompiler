"""Container layer: eval "basic" container + production ICB0 chunks (ic_decrypt port).

Eval chain (M4): payload (custom b64) -> magic dispatch 0x4ff571b7 ->
escdec 12-byte K -> len/seed -> pbl -> adler(a0=17) + MD4-fold verify ->
rol3key -> X3_(5) keystream -> triple-XOR plaintext (the main blob).

Production chain (M5-PROD): ICB0 prologue (per-PHP-version offset table) ->
'='-separated base64 chunks -> each chunk is its own basic container
(magic 45bfa667, fixed 8-byte adler field) -> stream region.
"""

import re
import struct

from .crypto.adler17 import adler17
from .crypto.b64_custom import b64_decode, chunk_split, payload_of
from .crypto.escdec import escdec
from .crypto.gen5 import Gen5
from .crypto.layerb import EVAL_KEY, component_decrypt
from .crypto.md4fold import md4, md4_fold, rol3_key
from .crypto.pbl import pbl_decode

MAGIC_EVAL = 0x4FF571B7
MAGIC_BASIC = 0x67A6BF45


def u32(b: bytes, o: int = 0) -> int:
    return struct.unpack_from("<I", b, o)[0]


def i32(b: bytes, o: int = 0) -> int:
    return struct.unpack_from("<i", b, o)[0]


def u16(b: bytes, o: int = 0) -> int:
    return struct.unpack_from("<H", b, o)[0]


def decrypt_file(path: str) -> dict:
    """The full eval chain for one file; verifies adler + MD4 fold."""
    with open(path, "rb") as f:
        data = f.read()
    return decrypt_data(data, path)


def decrypt_data(data: bytes, path: str = "<data>") -> dict:
    payload = payload_of(data)
    magic = u32(payload, 0)
    if (magic ^ 0x2853CEF2) & 0xFFFFFFFF != MAGIC_EVAL:
        raise ValueError(
            "not a basic container: magic 0x%08x (dispatch 0x%08x)"
            % (magic, (magic ^ 0x2853CEF2) & 0xFFFFFFFF)
        )
    K, kconsumed = escdec(payload, 4, 12)
    length = (((u32(K, 4) ^ 0x184FF593) + 0xF3DE98D2) & 0xFFFFFFFF) ^ u32(K, 8)
    seed = u32(K, 8)
    if length < 16 or length > len(payload):
        raise ValueError(f"implausible blob length {length}")
    cipher, postpbl = pbl_decode(payload, 28, length)

    stored, adler_end = escdec(payload, postpbl, 4)  # escdec returns an absolute position
    computed = adler17(payload[4:postpbl])
    adler_ok = u32(stored, 0) == computed

    rol3 = rol3_key(cipher[-16:])
    n = length - 16
    ks = Gen5(seed).bytes(n)
    plain = bytes(cipher[i] ^ ks[i] ^ rol3[i & 15] for i in range(n))
    fold = md4_fold(md4(plain), rol3)

    return {
        "payload": payload,
        "magic": magic,
        "key_hex": K.hex().upper(),
        "len": length,
        "seed": seed,
        "cipher": cipher,
        "plain": plain,
        "rol3key": rol3,
        "raw_region": f"payload[4..{postpbl})",
        "adler_stored": u32(stored, 0),
        "adler_computed": computed,
        "adler_ok": adler_ok,
        "adler_end": adler_end,
        "stream_seed": u32(payload, adler_end + 4),
        "reseed": u32(payload, adler_end + 8),
        "stream_region": (adler_end + 12, len(payload)),
        "md4_fold": fold,
        "ok": adler_ok and fold == 120,
    }


# ---------------- production (ICB0) ----------------


def prod_chunks(path: str) -> tuple[list[tuple[int, int]], list[bytes]]:
    """Parse the ICB0 prologue and split the payload into per-version chunks.

    Returns (fields, chunks): fields = [(php_version, offset), ...] from the
    prologue; chunks = decoded per-version container blobs.
    """
    with open(path, "rb") as f:
        d = f.read()
    n = d.find(b"\n")
    l0 = d[: n if n != -1 else 256]
    m = re.match(rb"^<\?php //ICB0 (.*?)\?>", l0)
    if not m:
        raise ValueError("no ICB0 prologue (not a production multi-version file?)")
    fields = [(int(v), int(h, 16)) for v, h in re.findall(rb"(\d+):([0-9a-f]+)", m.group(1))]
    i2 = l0.find(b"<?php //", 1)
    if i2 == -1:
        raise ValueError("cannot parse the version stub on line 0")
    sm = re.match(rb"^<\?php //([0-9a-f]{4,5})", l0[i2:])
    if not sm:
        raise ValueError("cannot parse the version stub on line 0")
    stub_off = int(sm.group(1), 16)
    b64start = i2 + stub_off + 4  # after the "\n?>\n" close-tag
    chunks = chunk_split(d[b64start:])
    if not chunks:
        raise ValueError("no base64 chunks found")
    return fields, chunks


def prod_container(c: bytes, label: str = "chunk") -> dict:
    """Parse one production chunk as a basic container (magic 45bfa667)."""
    if u32(c, 0) != MAGIC_BASIC:
        raise ValueError(f"{label}: magic {u32(c, 0):08x} is not the basic container 45bfa667")
    K, _ = escdec(c, 4, 12)  # header is a fixed 24 raw bytes
    length = (((u32(K, 4) ^ 0x184FF593) + 0xF3DE98D2) & 0xFFFFFFFF) ^ u32(K, 8)
    seed = u32(K, 8)
    if length < 16 or length > len(c):
        raise ValueError(f"{label}: implausible blob length {length}")
    blob, pbl_end = pbl_decode(c, 28, length)
    stored, _ = escdec(c, pbl_end, 4)
    return {
        "len": length,
        "seed": seed,
        "blob": blob,  # the pbl-decompressed main-blob ciphertext
        "pbl_end": pbl_end,
        "adler_ok": u32(stored, 0) == adler17(c[4:pbl_end]),
        "fieldA": u32(c, pbl_end + 4),  # raw 2nd half of the 8-byte adler field
        "stream_seed": u32(c, pbl_end + 8),
        "reseed": u32(c, pbl_end + 12),
        "region_off": pbl_end + 16,
    }


def layer_a(cipher: bytes, seed: int) -> bytes:
    """The eval decrypt core's triple-XOR, inline (M4 §3-5) — the chunk
    main-blob decrypt for production files."""
    last16 = cipher[-16:]
    rol3 = rol3_key(last16)
    ks = Gen5(seed).bytes(len(cipher) - 16)
    return bytes(cipher[i] ^ ks[i] ^ rol3[i & 15] for i in range(len(cipher) - 16))


def blob_signature() -> bytes:
    """The 4-byte ciphertext prefix of every component blob: keystream(eval
    key) ^ plaintext prefix 02 00 00 00 (the 1ea1e5ae signature)."""
    ks4 = component_decrypt(b"\0\0\0\0", EVAL_KEY)[:4]
    return bytes(a ^ b for a, b in zip(ks4, b"\x02\x00\x00\x00"))


def prod_blob_locate(stream: bytes) -> tuple[int, int, bytes, str] | None:
    """Locate the component ciphertext blob in a decoded component stream.

    Returns (offset, size, blob, method): 'conv' = the 0x4c conventional
    descriptor layout, 'sig' = the 1ea1e5ae signature scan fallback.
    """
    sig = blob_signature()
    size = u32(stream, 4)
    if 16 < size <= len(stream) and u32(stream, 0x48) == size and stream[0x4C:0x50] == sig:
        return 0x4C, size, stream[0x4C : 0x4C + size], "conv"
    lim = min(len(stream), 0x400)
    for i in range(0, lim - 3):
        if stream[i : i + 4] == sig and i + size <= len(stream):
            return i, size, stream[i : i + size], "sig"
    return None


def component_blob(stream: bytes) -> tuple[int, int, bytes]:
    """The eval-mode component locator: len word at 0x04, repeated at 0x48,
    blob at 0x4c (all three captured wires agree; ic_stream.php)."""
    size = u32(stream, 4)
    if size < 16 or 0x4C + size > len(stream):
        raise ValueError(f"component locator: implausible size {size} for stream of {len(stream)} bytes")
    if u32(stream, 0x48) != size:
        raise ValueError("component locator: len word not repeated at 0x48 (layout changed?)")
    return 0x4C, size, stream[0x4C : 0x4C + size]
