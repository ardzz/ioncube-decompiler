"""Layer-B component cipher (M4 §5): X3_(6) keyed by jenkins+murmur of the key.

w = jenkins_oaat(key) (signed bytes), z = murmur3_32(key, 0x1f);
out[i] = cipher[i] ^ ((mwc6_stream(w, z)[i] >> 8) & 0xff).

The eval/production component key is the 17-byte 0x01*16 + 0x00 (live-captured,
M4 §9 / M5-PROD). Byte-exact port of ic_decrypt.php component_decrypt() —
verified against the compdec_0001 gdb captures.
"""

from .mwc6 import mwc6_stream

M32 = 0xFFFFFFFF
EVAL_KEY = b"\x01" * 16 + b"\x00"


def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & M32


def jenkins_oaat(key: bytes) -> int:
    h = 0
    for b in key:
        if b >= 0x80:
            b -= 256  # loader uses movsbl (signed)
        h = (h + b) & M32
        h = (h + (h << 10)) & M32
        h ^= h >> 6
    h = (h + (h << 3)) & M32
    h ^= h >> 11
    h = (h + (h << 15)) & M32
    return h


def murmur3_32(key: bytes, seed: int) -> int:
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h = seed & M32
    n = len(key)
    nb = n & ~3
    for i in range(0, nb, 4):
        k = int.from_bytes(key[i:i + 4], "little")
        k = (k * c1) & M32
        k = _rol32(k, 15)
        k = (k * c2) & M32
        h ^= k
        h = _rol32(h, 13)
        h = (h * 5 + 0xE6546B64) & M32
    k = 0
    tail = key[nb:]
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & M32
        k = _rol32(k, 15)
        k = (k * c2) & M32
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & M32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & M32
    h ^= h >> 16
    return h


def component_decrypt(cipher: bytes, key: bytes) -> bytes:
    ks = mwc6_stream(jenkins_oaat(key), murmur3_32(key, 0x1F), len(cipher))
    return bytes(c ^ ((ks[i] >> 8) & 0xFF) for i, c in enumerate(cipher))
