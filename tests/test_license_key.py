"""The license dynamic-key property decoding and mask derivation."""

import pytest

from ioncube_re.license_key import (
    LicenseKeyError,
    decode_mykey,
    extract_license_key,
    mask_from_mykey,
)


def _property(value: bytes) -> bytes:
    """Build a synthetic __mykey wire value for a decimal payload."""
    key = (0xE9FC23B1).to_bytes(4, "little")
    payload = bytes(b ^ key[i % 4] for i, b in enumerate(value))
    return b"\x2d" + (len(value) ^ 0x23B1).to_bytes(2, "little") + payload


def test_synthetic_property_round_trip_and_mask():
    raw = _property(b"1234567")
    assert decode_mykey(raw) == 1234567
    assert mask_from_mykey(raw) == 1234567 // 7 - 13


def test_short_value_is_rejected():
    with pytest.raises(LicenseKeyError):
        decode_mykey(b"\x2d\x00")


def test_length_out_of_range_is_rejected():
    raw = b"\x2d" + (50 ^ 0x23B1).to_bytes(2, "little") + b"\x00" * 4
    with pytest.raises(LicenseKeyError):
        decode_mykey(raw)


def test_non_decimal_payload_is_rejected():
    with pytest.raises(LicenseKeyError):
        decode_mykey(_property(b"abc"))


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(LicenseKeyError):
        extract_license_key(str(tmp_path / "nope.php"))


def test_missing_bootstrap_is_rejected(tmp_path):
    encoded = tmp_path / "encoded.php"
    encoded.write_text("<?php\n", encoding="utf-8")
    with pytest.raises(LicenseKeyError):
        extract_license_key(
            str(encoded), bootstrap=str(tmp_path / "no-such-bootstrap.php")
        )
