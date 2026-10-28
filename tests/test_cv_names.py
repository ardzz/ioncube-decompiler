"""`cv_names` production pool ordering (regression).

The production pool is `[docblock][fnName][argnames][cvnames...][literals...]`.
The old code took the LAST numCV identifier-like entries as the CV names, but
trailing pool literals (billing-cycle names, status strings) are
identifier-like too, so literals stole CV slots and every name shifted by one.
`getBillingCycleDays` rendered `$Monthly`/`$Quarterly` for what are really
`$billingcycle`/`$totaldays`; `convertStateToCode` swapped its operands.

`cv_names`'s pool scan starts after the docblock+fnName, so the CV run begins
at the argument count.
"""

import struct

from ioncube_re.lift.signature import cv_names


def p32(v):
    return struct.pack("<I", v)


def make_r(pool, nargs, max_slot):
    hdr = bytearray(0x60)
    hdr[0x14:0x18] = p32(nargs)
    nodes = [{"ent": {"res": (8, max_slot)}}]
    return {
        "hdr": bytes(hdr),
        "pool": pool,
        "fnrec": b"\x01" * 16,
        "fn": 0,
        "pre": [],
        "nodes": nodes,
    }


def test_cv_names_start_after_args_not_at_tail():
    # fnName \0 arg \0 cv-param \0 cv-local \0 literal
    pool = (
        b"getBillingCycleDays\x00"   # fnName (skipped by the pool scan)
        b"billingcycle\x00"          # arg (slot 0)
        b"billingcycle\x00"          # cv slot 0 (params repeat)
        b"totaldays\x00"             # cv slot 1
        b"Monthly\x00"               # pool literal, not a CV
    )
    r = make_r(pool, nargs=1, max_slot=1)
    assert cv_names(r, "prod", []) == {0: "billingcycle", 1: "totaldays"}


def test_cv_names_multi_arg():
    pool = (
        b"convertStateToCode\x00"      # fnName (skipped by the pool scan)
        b"ostate\x00country\x00"      # args
        b"ostate\x00country\x00"      # cv slots 0,1
        b"sc\x00state\x00"            # cv slots 2,3
        b"US\x00"                     # literal
    )
    r = make_r(pool, nargs=2, max_slot=3)
    assert cv_names(r, "prod", []) == {
        0: "ostate", 1: "country", 2: "sc", 3: "state",
    }
