"""Offline keytable derivation (M6-KEYTAB.md — the Wc9 formula, live-validated).

ktab[i] = MWC6(seedA, seedB)[i] ^ ierg, for i in 0..thr — packed u32-LE.
  seedA/seedB = the stream-descriptor u32s (+0x14/+0x18 in memory,
                [0x08]/[0x0c] in the stream blob);
  ierg        = u32 at the decrypted main blob +0x14 (per encoding batch);
  X           = u32 at main blob +0x1c (2 = the eval encoder, 6 = CE 8.4
                chunks) — the K2 mask offset and the wD0 variant selector.

The mask forms (per node i, raw = op & 0xff):
  v>5 (sig mode):  final = raw ^ K1 ^ K2,  K1 = ktab[i], K2 = ktab[thr+X+i]
  v<=5 (nosig):    final = raw ^ K1
"""

import struct

from .mwc6 import mwc6_stream


def kt_generate(seed_a: int, seed_b: int, ierg: int, thr: int) -> bytes:
    """(thr+1) keytable u32s, little-endian — byte-exact vs the m5 ktab dumps."""
    ks = mwc6_stream(seed_a, seed_b, thr + 1)
    return struct.pack("<%dI" % (thr + 1), *((v ^ ierg) & 0xFFFFFFFF for v in ks))
