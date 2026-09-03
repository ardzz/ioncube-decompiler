"""adler-32 with a0=17, b0=0 (loader 0x4885f: r15 starts at 0x11) — layer-A integrity."""

MOD = 65521


def adler17(data: bytes) -> int:
    a = 17
    b = 0
    for c in data:
        a = (a + c) % MOD
        b = (b + a) % MOD
    return (b << 16) | a
