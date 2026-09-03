"""MD4 + the keyed integrity fold (loader 0x40c60/0x4121d is MD4, NOT MD5; fold at 0x48b60).

The fold: sum((D[i] ^ rol3key[i]) + i) for i in 0..15 == 120 on valid files,
where D = MD4(plain). hashlib does not carry MD4 on OpenSSL-3 builds, so this
is a compact pure-Python RFC-1186 MD4 (validated against PHP hash('md4')).
"""

import struct

_M32 = 0xFFFFFFFF


def _f(x: int, y: int, z: int) -> int:
    return (x & y) | (~x & z)


def _g(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)


def _h(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M32


_R1 = (3, 7, 11, 19)
_R2 = (3, 5, 9, 13)
_R3 = (3, 9, 11, 15)
_IDX2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
_IDX3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
_C2 = 0x5A827999
_C3 = 0x6ED9EBA1


def md4(data: bytes) -> bytes:
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    # padding: 0x80, zeros, 64-bit little-endian bit length
    padded = data + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    padded += struct.pack("<Q", len(data) * 8)
    for off in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[off:off + 64])
        a, b, c, d = a0, b0, c0, d0
        # round 1
        for i in range(16):
            k = i
            v = _rol((a + _f(b, c, d) + x[k]) & _M32, _R1[i & 3])
            a, b, c, d = d, v, b, c
        # round 2
        for i in range(16):
            k = _IDX2[i]
            v = _rol((a + _g(b, c, d) + x[k] + _C2) & _M32, _R2[i & 3])
            a, b, c, d = d, v, b, c
        # round 3
        for i in range(16):
            k = _IDX3[i]
            v = _rol((a + _h(b, c, d) + x[k] + _C3) & _M32, _R3[i & 3])
            a, b, c, d = d, v, b, c
        a0 = (a0 + a) & _M32
        b0 = (b0 + b) & _M32
        c0 = (c0 + c) & _M32
        d0 = (d0 + d) & _M32
    return struct.pack("<4I", a0, b0, c0, d0)


def md4_fold(d: bytes, rol3key: bytes) -> int:
    return sum((d[i] ^ rol3key[i]) + i for i in range(16))


def rol3_key(last16: bytes) -> bytes:
    return bytes(((b << 3) | (b >> 5)) & 0xFF for b in last16)
