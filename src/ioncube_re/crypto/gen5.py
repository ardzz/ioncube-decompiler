"""X3_(5) CMWC-hybrid PRNG (seeder 0x106335, gen 0x1064a5) — the layer-A keystream.

CMWC4096 (a=18782) mixed with an LCG(69069) and a parity-selected xorshift;
1 low byte per output. Byte-exact port of ic_decrypt.php IcGen5 (validated
against live gdb captures — M4-KEYSTREAM.md §8).
"""

M32 = 0xFFFFFFFF
N = 4096


class Gen5:
    __slots__ = ("mt", "mti", "Q", "c32", "carry", "odd")

    def __init__(self, seed: int):
        seed &= M32
        self.Q = (seed * 69069 + 0x12D687) & M32
        c = seed
        for _ in range(seed % 9):
            c = (c ^ ((c << 10) & M32)) & M32
            c ^= c >> 15
            c = (c ^ ((c << 4) & M32)) & M32
            c ^= c >> 13
        self.c32 = c
        self.carry = seed % 18782
        # the xorshift variant is fixed at seed time by the seed's parity
        self.odd = (seed & 1) == 1
        self.mt = [0] * N
        for i in range(N):
            self.Q = (self.Q * 69069 + 0x7B) & M32
            self.c32 = self._xs(self.c32)
            self.mt[i] = (self.Q + self.c32) & M32
        self.mti = N - 1

    def _xs(self, x: int) -> int:
        if self.odd:  # 0x10630b: x^=x<<13; x^=x>>17; x^=x<<5
            x = (x ^ ((x << 13) & M32)) & M32
            x ^= x >> 17
            return (x ^ ((x << 5) & M32)) & M32
        # 0x106321: x^=x>>9; x^=x<<1; x^=x>>7
        x ^= x >> 9
        x = (x ^ ((x << 1) & M32)) & M32
        x ^= x >> 7
        return x

    def next(self) -> int:  # gen5, 0x1064a5
        if self.mti >= N:
            for k in range(N):
                self.mti = (self.mti + 1) & (N - 1)
                t = 18782 * self.mt[self.mti] + self.carry  # < 2^45, exact
                self.carry = (t >> 32) & M32
                lo = t & M32
                s = lo + self.carry
                if s > M32:
                    x = (s + 1) & M32
                    self.carry = (self.carry + 1) & M32
                else:
                    x = s
                if x == M32:
                    self.carry = (self.carry + 1) & M32
                    x = 0
                cmwc = (0xFFFFFFFE - x) & M32
                self.mt[self.mti] = cmwc
                self.Q = (self.Q * 69069 + 0x7B) & M32
                self.c32 = self._xs(self.c32)
                self.mt[k] = (self.Q + self.c32 + cmwc) & M32
            self.mti = 0
        v = self.mt[self.mti]
        self.mti += 1
        return v

    def bytes(self, n: int) -> bytes:
        return bytes(self.next() & 0xFF for _ in range(n))
