"""X3_(6) dual-16-bit MWC (FUN_002065c6) — the layer-B / keytable generator.

z' = (z>>16) + (z&0xffff)*30345;  w' = (w>>16) + (w&0xffff)*18000;
out = ROL16(z') + w'   (all mod 2^32).

The keytable (M6-KEYTAB.md) packs (thr+1) outputs u32-LE, each XORed with
ierg; the layer-B component cipher consumes (out >> 8) & 0xff per byte.
The cache/rewind armature of the full X3_(6) object is never armed on any
captured path (M6-KEYTAB §2) — the raw stepping below is byte-identical.
"""

M32 = 0xFFFFFFFF


def mwc6_stream(w: int, z: int, n: int) -> list[int]:
    """n outputs of the dual-16-bit MWC seeded with (w, z)."""
    out = []
    w &= M32
    z &= M32
    for _ in range(n):
        z = ((z >> 16) + (z & 0xFFFF) * 30345) & M32
        w = ((w >> 16) + (w & 0xFFFF) * 18000) & M32
        rol16 = ((z << 16) | (z >> 16)) & M32
        out.append((rol16 + w) & M32)
    return out
