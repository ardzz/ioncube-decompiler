"""Crypto-layer unit tests: byte-exact vs the live-captured m4/m5 dumps.

Covers: MD4 (pure-python, vs RFC vectors), escdec (keyhdr -> K), pbl
(payload -> cipher), adler17, the layer-B component cipher (ccipher ->
compdec), jenkins/murmur (the eval-key hashes live-captured in M6-KEYTAB),
the X3_(5) keystream (full 172/172 chain), and the offline keytable (ktab
dumps, 11/11 — the M6-KEYTAB §5.1 table).
"""

import glob
import struct

from ioncube_re.crypto.adler17 import adler17
from ioncube_re.crypto.b64_custom import payload_of
from ioncube_re.crypto.escdec import escdec
from ioncube_re.crypto.gen5 import Gen5
from ioncube_re.crypto.keytable import kt_generate
from ioncube_re.crypto.layerb import (
    EVAL_KEY,
    component_decrypt,
    jenkins_oaat,
    murmur3_32,
)
from ioncube_re.crypto.md4fold import md4, md4_fold, rol3_key
from ioncube_re.crypto.pbl import pbl_decode

from conftest import M4, M5, WORK, requires_workspace

SAMPLES = ("marker81", "hello81", "fresh81")


def _m4(sample, pattern):
    return sorted(glob.glob(f"{M4}/{sample}/{pattern}"))[0]


def test_md4_rfc_vectors():
    # 'abc' + empty from RFC 1186; the length-boundary vectors cross-checked
    # against PHP hash('md4') (the oracle's own MD4)
    assert md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    for n, want in ((55, "c889c81dd86c4d2e025778944ea02881"),
                    (56, "d5f9a9e9257077a5f08b0b92f348b0ad"),
                    (57, "872097e6f78e3b53f890459d03bc6fb7"),
                    (64, "52f5076fabd22680234a3fa9f9dc5732"),
                    (1000, "5f1bf26a8067c9159b91f1440f7c9e8a")):
        assert md4(b"a" * n).hex() == want


def test_jenkins_murmur_eval_key():
    # live-captured (M6-KEYTAB §2): s9w(X3_(6), jenkins(key), murmur(key, 0x1f))
    # with the 17-byte eval key -> (0xc1cfb022, 0x193b0993)
    assert jenkins_oaat(EVAL_KEY) == 0xC1CFB022
    assert murmur3_32(EVAL_KEY, 0x1F) == 0x193B0993


@requires_workspace
def test_escdec_key_headers():
    for s in SAMPLES:
        payload = payload_of(open(f"{WORK}/{s}.php", "rb").read())
        K, consumed = escdec(payload, 4, 12)
        assert K == open(_m4(s, "key_0001_*_12B.bin"), "rb").read()
        assert payload[4:28] == open(_m4(s, "keyhdr_0000_*_24B.bin"), "rb").read()
        assert consumed >= 16


@requires_workspace
def test_pbl_ciphers_and_adler():
    for s in SAMPLES:
        payload = payload_of(open(f"{WORK}/{s}.php", "rb").read())
        K, _ = escdec(payload, 4, 12)
        length = ((((int.from_bytes(K[4:8], "little") ^ 0x184FF593)
                    + 0xF3DE98D2) & 0xFFFFFFFF) ^ int.from_bytes(K[8:12], "little"))
        cipher, postpbl = pbl_decode(payload, 28, length)
        assert cipher == open(_m4(s, "cipher_0001_*_188B.bin"), "rb").read()
        stored, _ = escdec(payload, postpbl, 4)
        assert adler17(payload[4:postpbl]) == int.from_bytes(stored, "little")


@requires_workspace
def test_gen5_keystream_full_chain_172():
    """plain[i] = cipher[i] ^ ks[i] ^ rol3[i&15] vs the LIVE decrypted buffers."""
    for s in SAMPLES:
        payload = payload_of(open(f"{WORK}/{s}.php", "rb").read())
        K, _ = escdec(payload, 4, 12)
        seed = int.from_bytes(K[8:12], "little")
        length = ((((int.from_bytes(K[4:8], "little") ^ 0x184FF593)
                    + 0xF3DE98D2) & 0xFFFFFFFF) ^ seed)
        cipher, _ = pbl_decode(payload, 28, length)
        rol3 = rol3_key(cipher[-16:])
        n = length - 16
        ks = Gen5(seed).bytes(n)
        plain = bytes(cipher[i] ^ ks[i] ^ rol3[i & 15] for i in range(n))
        live = open(_m4(s, "plain_0001_*_188B.bin"), "rb").read()
        # live in-place buffer = plain + the untouched rol3 tail
        assert plain + cipher[-16:] == live
        assert md4_fold(md4(plain), rol3) == 120


@requires_workspace
def test_layerb_component_cipher():
    """ccipher_0000 -> compdec_0001, byte-exact (the M4 §8 COMPONENT_BYTE_MATCH)."""
    for s in SAMPLES:
        cc = open(_m4(s, "ccipher_0000_*B.bin"), "rb").read()
        cd = open(_m4(s, "compdec_0001_*B.bin"), "rb").read()
        assert component_decrypt(cc, EVAL_KEY) == cd
        ckey = open(_m4(s, "ckey_0000_*_17B.bin"), "rb").read()
        assert ckey == EVAL_KEY  # the live-captured 17-byte eval key


# ---- the M6-KEYTAB §5.1 table: 11/11 eval components, ktab byte-exact ----

_KT_EVAL = [
    # (sample, component, thr, seedA, seedB, ierg)
    ("marker81", "ktab_0001", 5, 0x5E7A8FC5, 0x0921931B, 0x363A68),
    ("marker81", "ktab_0002", 6, 0x688B35AA, 0x1047F732, 0x363A68),
    ("fresh81", "ktab_0001", 5, 0x73BB48D9, 0x7586355F, 0x365721),
    ("fresh81", "ktab_0002", 6, 0x58583FEF, 0x30F905E6, 0x365721),
    ("gt_diverse1", "ktab_0001", 21, 0x40F7E58A, 0x039376DF, 0x36850D),
    ("gt_diverse2", "ktab_0001", 40, 0x40F7E58A, 0x039376DF, 0x36850D),
    ("gt_diverse2", "ktab_0002", 8, 0x0E3DA346, 0x752801CE, 0x36850D),
    ("gt_diverse3", "ktab_0001", 14, 0x40F7E58A, 0x039376DF, 0x36850D),
    ("gt_diverse3", "ktab_0002", 4, 0x170897E0, 0x25D52582, 0x36850D),
    ("gt_diverse3", "ktab_0003", 7, 0x236DE1E2, 0x39B8318B, 0x36850D),
    ("gt_diverse3", "ktab_0004", 5, 0x08249A8C, 0x3F61D006, 0x36850D),
]


@requires_workspace
def test_keytable_11_components():
    for sample, kname, thr, sa, sb, ierg in _KT_EVAL:
        kt = kt_generate(sa, sb, ierg, thr)
        gt = sorted(glob.glob(f"{M5}/{sample}/{kname}_*.bin"))[0]
        ref = open(gt, "rb").read()
        # the m5 dumps are truncated at min(thr, 16) bytes (M5 §7.8)
        assert kt[: len(ref)] == ref, f"{sample}/{kname}"
