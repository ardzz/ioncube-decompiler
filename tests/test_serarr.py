"""Serialized constant-array tests (SERARR-PORT — the dawwinci grammar port).

Fixtures under tests/data/ are the corpus zval blobs (extracted from the
research-workspace pools — the vendor files themselves stay out of the repo):
  * the eval gt_diverse2 zval0 — M6-OPERANDS §7.7's "1:0s5'alpha..." sample,
    byte-verified against the M5 ground truth ['alpha','beta','gamma'];
  * Blesta license.php c2 load()'s arrays — the decodephp.io ground truth
    (notes/BENCHMARK-DECODEPHP.md): $possible_license_hashes (2 sha256 hex
    strings), $signatures (empty), $libraries (5 phpseclib class keys => 2
    hash strings each), and the status-code map;
  * CE api_index / upgrade_5_0_0RC3 / TaxGateway blobs — the DAWWINCI-DIFF
    §3 byte-verification samples (string-key maps, int values, nesting).

The workspace-dependent tests re-derive the blobs live through the full
decode chain and sweep all 15 CE type=307 zvals (DAWWINCI-DIFF §3's corpus
sweep) plus the lift-time emission of the license.php literals.
"""

import pytest

from ioncube_re.serarr import decode_serarr, php_array_literal

from conftest import CE, WORK, requires_workspace

DATA = __file__.rsplit("/", 1)[0] + "/data"


def blob(name: str) -> bytes:
    with open(f"{DATA}/{name}", "rb") as f:
        return f.read()


# ---- the decodephp.io ground truth (license.php load()) ----

HASHES = [
    "9c3ed7b1e982552bb3f88c4ad8d284ae5e1af90e06b5aa56ef58869d896b0b91",
    "0a994a53f85e7fa2e365b5523d2eac777e9fb18886f89305bc292c416e5b7329",
]
LIB_KEYS = ["phpseclib\\Crypt\\AES", "phpseclib\\Crypt\\Hash",
            "phpseclib\\Crypt\\Rijndael", "phpseclib\\Crypt\\RSA",
            "phpseclib\\Math\\BigInteger"]
LIB_HASHES = [
    "3a90ed03878cac65d6082780ad2e579cd34daffd4ed253ef377a10ddecf33240",
    "ba3168dea4a6f45303599879ee17aea0ccfeaee1267c4c43f46b2f55e8401d87",
    "34c81b06159e228827120943caaeb4bbfed955395def9de97dd3f7263ec308f1",
    "932102c94f9cae2d3b5e08535afe4075478facfdac527d92ef00f873659d5c91",
    "8d38ab84e003c1fdbc191cc50d1869f36f60bcbb5fa41cc7216db4e9fad547c1",
    "31e9d99761f8c49c3d1d1e266b6267c9a1b5e7eb54656f9a1eb50107adf091c9",
    "dec7c41d480f9b46b66caa455806411ee5dc2645870a47505a1f10d89077b65a",
    "9e6e846c8a66b321ce0ddaeeaedfe1ec7872278ac6ce00164ae5cb6542e41686",
    "9013f8cf55dfd8dfe224c49c52f47c1be9ed669981b60395ca91c6027ba0fe27",
    "1253b289cec9fb838373ea958b453d9a2bdc07b1fe3536ff721c4163b04d540c",
]


# ---- fixture decodes (no workspace needed) ----

def test_gt_diverse2_zval0():
    """M6 §7.7's eval sample: [(0,'alpha'),(1,'beta'),(2,'gamma')], all 80
    bytes consumed (the M5 gt is $items = ['alpha','beta','gamma'])."""
    pairs = decode_serarr(blob("gt_diverse2_zval0.bin"), exact=True)
    assert pairs == [(0, "alpha"), (1, "beta"), (2, "gamma")]
    assert php_array_literal(pairs) == "['alpha', 'beta', 'gamma']"


def test_license_possible_license_hashes():
    pairs = decode_serarr(blob("license_possible_license_hashes.bin"), exact=True)
    assert pairs == [(0, HASHES[0]), (1, HASHES[1])]
    assert php_array_literal(pairs) == "['%s', '%s']" % tuple(HASHES)


def test_license_signatures_empty():
    assert decode_serarr(blob("license_signatures_empty.bin"), exact=True) == []
    assert php_array_literal([]) == "[]"


def test_license_libraries_decodephp_ground_truth():
    """$libraries: 5 string keys (exact order) => 2-hash arrays — the 10 hash
    strings byte-for-byte on values and key order vs the decodephp preview."""
    pairs = decode_serarr(blob("license_libraries.bin"), exact=True)
    assert [k for k, _ in pairs] == LIB_KEYS
    values = [v for _, v in pairs]
    assert all(isinstance(v, list) and len(v) == 2 for v in values)
    assert [(k, v) for p in values for k, v in p] == [
        (0, LIB_HASHES[0]), (1, LIB_HASHES[1]),
        (0, LIB_HASHES[2]), (1, LIB_HASHES[3]),
        (0, LIB_HASHES[4]), (1, LIB_HASHES[5]),
        (0, LIB_HASHES[6]), (1, LIB_HASHES[7]),
        (0, LIB_HASHES[8]), (1, LIB_HASHES[9]),
    ]
    lit = php_array_literal(pairs)
    # the rendered literal carries every key and hash, nested two deep
    assert lit.startswith("['phpseclib\\\\Crypt\\\\AES' => ['%s', '%s']" % (LIB_HASHES[0], LIB_HASHES[1]))
    assert lit.endswith("'%s', '%s']]" % (LIB_HASHES[8], LIB_HASHES[9]))
    assert lit.count(" => ") == 5
    for h in LIB_HASHES:
        assert f"'{h}'" in lit


def test_license_status_map():
    """String keys => int values (license.php getStatistics()' status map)."""
    pairs = decode_serarr(blob("license_status_map.bin"), exact=True)
    assert pairs == [
        ("invalid_location", 16), ("suspended", 18), ("expired", 20),
        ("unknown", 32), ("company_quota", 44), ("unsupported_version", 46),
    ]


def test_api_index_string_key_map():
    """DAWWINCI-DIFF §3: the 4-entry string-keyed map, exact."""
    pairs = decode_serarr(blob("api_index_zval24_map.bin"), exact=True)
    assert pairs == [("kb", "knowledgebase"), ("accounts", "clients"),
                     ("core", "admin"), ("supportexec", "support")]


def test_api_index_init():
    assert decode_serarr(blob("api_index_zval27_init.bin"), exact=True) == [(0, "init")]


def test_api_index_verbs():
    pairs = decode_serarr(blob("api_index_zval30_verbs.bin"), exact=True)
    assert pairs == [("get", 42), ("put", 192), ("post", 337)]
    assert php_array_literal(pairs) == "['get' => 42, 'put' => 192, 'post' => 337]"


def test_upgrade_gateways():
    """DAWWINCI-DIFF §3: 8 int-keyed gateway names."""
    pairs = decode_serarr(blob("upgrade_5_0_0RC3_zval0_gateways.bin"), exact=True)
    assert pairs == [(i, n) for i, n in enumerate(
        ("authnet", "bluepay", "eprocessingnetwork", "eway",
         "globalpay", "paypalpro", "psigate", "quantum"))]


def test_taxgateway_verbs_and_nested():
    assert decode_serarr(blob("taxgateway_zval5_verbs.bin"), exact=True) == [
        ("POST", 18), ("PATCH", 25), ("GET", 32)]
    assert decode_serarr(blob("taxgateway_zval33_socket.bin"), exact=True) == [
        ("socket", [("bindto", "0.0.0.0:0")])]


# ---- grammar unit cases (synthetic) ----

def _ser(*entries: str, trailer: str = "20;775;0;1;7;") -> bytes:
    return ("[" + "".join(entries) + "}" + trailer).encode()


def test_synthetic_scalar_types():
    assert decode_serarr(_ser("1:0i42;0;1;", "1:1i-7;0;1;"), exact=True) == [(0, 42), (1, -7)]
    assert decode_serarr(_ser("1:0d1.5;0;1;"), exact=True) == [(0, 1.5)]
    assert decode_serarr(_ser("1:0b1;0;1;", "1:1b0;0;1;"), exact=True) == [(0, True), (1, False)]
    assert decode_serarr(_ser("1:0s3'abc0;0;2;22;"), exact=True) == [(0, "abc")]


def test_synthetic_nested_and_mixed_keys():
    nested = _ser("1:0i1;0;1;", trailer="9;9;0;1;7;")
    pairs = decode_serarr(_ser("2'ab" + nested.decode("latin-1"), "3:10i2;0;1;"), exact=True)
    assert pairs == [("ab", [(0, 1)]), (10, 2)]


def test_prefix_and_malformed():
    good = _ser("1:0i1;0;1;")
    assert decode_serarr(b"\x81" + good, exact=True) == [(0, 1)]  # prod pool prefix
    assert decode_serarr(b"") is None
    assert decode_serarr(b"garbage") is None
    assert decode_serarr(b"[") is None
    assert decode_serarr(b"[1:0") is None
    assert decode_serarr(b"[1:0i1;") is None  # truncated trailer
    assert decode_serarr(b"[x}'") is None


def test_literal_quoting():
    assert php_array_literal([("k's", "v")]) == """['k\\'s' => 'v']"""
    assert php_array_literal([("a\\b", 1)]) == """['a\\\\b' => 1]"""
    assert php_array_literal([(0, "it's")]) == "['it\\'s']"
    assert php_array_literal([(2, "x")]) == "[2 => 'x']"  # non-sequential int key
    assert php_array_literal([(0, True), (1, False)]) == "[true, false]"
    assert php_array_literal([(0, 1.5)]) == "[1.5]"


# ---- workspace-dependent: live corpora through the decode chain ----


@requires_workspace
def test_ce_15_type307_zvals_all_decode():
    """DAWWINCI-DIFF §3's corpus sweep: 15 type=307 array zvals in 9 chunk
    wires from 3 CE files (plus the 6 type=007 empty arrays), every one
    decoding with full byte consumption."""
    from ioncube_re.container import prod_blob_locate
    from ioncube_re.crypto.layerb import EVAL_KEY, component_decrypt
    from ioncube_re.stream import prod_decode_file
    from ioncube_re.wire import parse_wire

    files = [
        f"{CE}/api/index.php",
        f"{CE}/library/setup/scripts/upgrade_5_0_0RC3.php",
        f"{CE}/library/setup/scripts/upgrade_6_6_1a1.php",
    ]
    n307 = 0
    n007 = 0
    for path in files:
        for chunk in (1, 2, 3):
            stream = prod_decode_file(path, chunk)["chunks"][0]["stream"]
            loc = prod_blob_locate(stream)
            r = parse_wire(component_decrypt(loc[2], EVAL_KEY))
            for z in r["zvals"]:
                if (z["type"] & 0xFF) != 7 or "str" not in z:
                    continue
                assert decode_serarr(z["str"], exact=True) is not None
                if z["type"] == 0x307:
                    n307 += 1
                else:
                    n007 += 1
    assert n307 == 15
    assert n007 == 6


@requires_workspace
def test_gt_diverse2_zval0_live_pipeline():
    from ioncube_re.container import prod_blob_locate
    from ioncube_re.crypto.layerb import EVAL_KEY, component_decrypt
    from ioncube_re.stream import stream_of_file
    from ioncube_re.wire import parse_wire

    stream = stream_of_file(f"{WORK}/gt_diverse2_81.php")["stream"]
    loc = prod_blob_locate(stream)
    r = parse_wire(component_decrypt(loc[2], EVAL_KEY))
    z = r["zvals"][0]
    assert z["type"] == 0x307 and z["len"] == 80
    assert decode_serarr(z["str"], exact=True) == [(0, "alpha"), (1, "beta"), (2, "gamma")]


@requires_workspace
def test_license_lift_emits_decodephp_arrays():
    """The acceptance test: license.php c2 load() emits $possible_license_hashes,
    $signatures and $libraries as COMPLETE array literals matching the
    decodephp.io ground truth (values byte-for-byte, key order too)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{WORK}/corpus/blesta/blesta/app/models/license.php", chunk=2)
    t = r["text"]
    assert "$possible_license_hashes = ['%s', '%s'];" % tuple(HASHES) in t
    assert "$signatures = [];" in t
    assert "$libraries = ['phpseclib\\\\Crypt\\\\AES' => ['%s', '%s']" % (LIB_HASHES[0], LIB_HASHES[1]) in t
    for k in LIB_KEYS[1:]:  # the emitted literal escapes the backslashes
        assert f"'{k.replace(chr(92), chr(92) * 2)}' => [" in t
    for h in LIB_HASHES:
        assert f"'{h}'" in t
    assert "/* serialized array" not in t
    assert "/* +ser */" not in t
    assert "foreach ($libraries as $class => $hashes) {" in t


@requires_workspace
def test_ce_taxgateway_arrays_lift():
    """TaxGateway c1: the socket nested array renders as a real literal inside
    ValidateVAT's stream_context_create argument. (Before the handlers port
    the second copy lived inside an unknown-opcode fallback comment carrying
    the zval text; the SWITCH_STRING-header ungarble turned that node into
    bookkeeping, so exactly one clean literal remains.) The verbs map
    (['POST' => 18, ...]) is consumed by the same header — covered by the
    fixture decode test instead (the emitter-coverage gap, DAWWINCI-DIFF
    §5 item 2)."""
    from ioncube_re.lift import lift_file

    r = lift_file(f"{CE}/modules/billing/models/TaxGateway.php")
    t = r["text"]
    assert t.count("'socket' => ['bindto' => '0.0.0.0:0']") == 1
    assert "stream_context_create(['socket' => ['bindto' => '0.0.0.0:0']])" in t
