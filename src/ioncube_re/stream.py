"""Layer-C/D component-stream codec (ic_stream port, M5-FROB / M5-PROD).

Layer C "frame codec" (readerA refill 0x10c1d7+): 2-byte control frames —
  b0 < 0x80          -> b1 data bytes XORed with the X3_(5) keystream seeded
                        by the payload STREAM SEED; reader adler (init 0) over
                        the consumed raw bytes with escdec-coded 4-byte
                        checkpoints (b0 & 0xe0 == 0xa0);
  (b0 & 0xe0)==0xa0  -> escdec 4-byte adler checkpoint (validated);
  ==0xc0             -> literal 0x3c (adler over the pair);
  ==0x80             -> literal b1 (adler over the pair);
  0xe0..0xff         -> skip (no output, no adler).
Layer D "frob" = RFC 1951 raw DEFLATE (zlib windowBits=-15).

Raises StreamError on any checkpoint mismatch or inflate failure (the PHP
tool exits 2 there; the CLI maps StreamError -> exit 2).
"""

import zlib

from .container import (
    component_blob,
    decrypt_file,
    prod_blob_locate,
    prod_chunks,
    prod_container,
    u32,
)
from .crypto.escdec import escdec
from .crypto.gen5 import Gen5
from .crypto.layerb import EVAL_KEY, component_decrypt


class StreamError(Exception):
    pass


def frame_decode(raw: bytes, seed: int) -> tuple[bytes, int, int, int]:
    """Decode the frame codec; returns (intermediate, frames, checkpoints, adler).

    The reader adler is adler-32 with s1/s2 init 0 — computed with
    zlib.adler32 (identical modular arithmetic; the NMAX=5552 blocking the
    PHP oracle performs per data frame is not observable in the result)."""
    gen = Gen5(seed)
    s = 0  # (s2 << 16) | s1
    out = bytearray()
    pos = 0
    n = len(raw)
    frames = 0
    checkpoints = 0
    while pos < n:
        b0 = raw[pos]
        b1 = raw[pos + 1] if pos + 1 < n else 0
        if b0 < 0x80:  # data frame: b1 bytes XOR keystream
            cnt = b1
            s = zlib.adler32(raw[pos : pos + 2 + cnt], s)
            if cnt:
                ks = gen.bytes(cnt)
                out += bytes(a ^ b for a, b in zip(raw[pos + 2 : pos + 2 + cnt], ks))
            pos += 2 + cnt
            frames += 1
        elif (b0 & 0xE0) == 0xA0:  # escdec 4-byte adler checkpoint
            p = pos + 1
            esc = bytearray()
            while len(esc) < 4:
                if p >= n:
                    raise StreamError(f"frame codec: truncated adler checkpoint at raw offset {pos}")
                b = raw[p]
                if b == 0xFF:
                    if p + 1 >= n:
                        raise StreamError(f"frame codec: dangling 0xff in checkpoint at {p}")
                    esc.append(0x3C if (raw[p + 1] & 0x80) else 0xFF)
                    p += 2
                else:
                    esc.append(b)
                    p += 1
            stored = u32(esc)
            if stored != (s & 0xFFFFFFFF):
                raise StreamError(
                    "frame codec: adler checkpoint mismatch at raw offset 0x%x (stored %08x, running %08x)"
                    % (pos, stored, s)
                )
            pos = p
            checkpoints += 1
        elif (b0 & 0xE0) == 0xC0:  # literal 0x3c, adler over the pair
            out.append(0x3C)
            s = zlib.adler32(raw[pos : pos + 2], s)
            pos += 2
            frames += 1
        elif (b0 & 0xE0) == 0x80:  # literal b1, adler over the pair
            out.append(b1)
            s = zlib.adler32(raw[pos : pos + 2], s)
            pos += 2
            frames += 1
        else:  # 0xe0..0xff: skip, no output/adler
            pos += 2
            frames += 1
    return bytes(out), frames, checkpoints, s


def frob_decode(inter: bytes) -> bytes:
    """Layer D: the 'frob' codec is raw DEFLATE (RFC 1951)."""
    try:
        return zlib.decompress(inter, -15)
    except zlib.error as e:
        raise StreamError(f"frob (deflate): inflate failed on the intermediate buffer: {e}") from e


def decode_raw(raw: bytes, seed: int, region_off: int = 0) -> dict:
    inter, frames, checkpoints, adler = frame_decode(raw, seed)
    stream = frob_decode(inter)
    return {
        "raw": raw,
        "seed": seed,
        "region_off": region_off,
        "inter": inter,
        "frames": frames,
        "checkpoints": checkpoints,
        "frame_adler": "%08x" % adler,
        "stream": stream,
    }


def stream_of_file(path: str) -> dict:
    """The full eval offline chain: decrypt (verifies adler+MD4) -> frames -> deflate."""
    r = decrypt_file(path)
    off, end = r["stream_region"]
    raw = r["payload"][off:end]
    return decode_raw(raw, r["stream_seed"], off)


def prod_decode_file(path: str, only: int | None = None) -> dict:
    """The production chain: ICB0 -> chunks -> containers -> frame codec ->
    deflate -> component blob locate + layer-B decrypt, per chunk."""
    fields, chunks = prod_chunks(path)
    out = {"fields": fields, "chunks": []}
    for idx, c in enumerate(chunks):
        n = idx + 1
        if only is not None and only != n:
            continue
        r = prod_container(c, f"chunk{n}")
        r["num"] = n
        raw = c[r["region_off"]:]
        inter, frames, ckpts, adler = frame_decode(raw, r["stream_seed"])
        stream = frob_decode(inter)
        r["inter"] = inter
        r["stream"] = stream
        r["frames"] = frames
        r["ckpts"] = ckpts
        r["region_len"] = len(raw)
        r["container_len"] = len(c)
        loc = prod_blob_locate(stream)
        if loc is not None:
            coff, size, blob, method = loc
            r["blob_off"] = coff
            r["blob"] = blob
            r["blob_method"] = method
            r["plain"] = component_decrypt(blob, EVAL_KEY)
        out["chunks"].append(r)
    return out


# ---------------- verify helpers (ic_stream --verify) ----------------


def readers_concat(files: list[str]) -> tuple[bytes, int]:
    """Concatenate readerA dump files ordered by their hit index (_NNNN_)."""
    import os
    import re

    def hit(p: str) -> int:
        m = re.search(r"_(\d+)_", os.path.basename(p))
        return int(m.group(1)) if m else 0

    files = sorted(files, key=hit)
    cat = b""
    for f in files:
        with open(f, "rb") as fh:
            cat += fh.read()
    return cat, len(files)


def verify_stream(stream: bytes, files: list[str]) -> tuple[bool, str]:
    """Byte-compare the decoded stream vs the concatenated readerA dumps."""
    cat, count = readers_concat(files)
    n = min(len(stream), len(cat))
    mism = 0
    first = -1
    for i in range(n):
        if stream[i] != cat[i]:
            if first < 0:
                first = i
            mism += 1
    report = "VERIFY: decoded %d B vs concatenated readerA dumps: %d dumps, %d bytes total\n" % (
        len(stream),
        count,
        len(cat),
    )
    if mism == 0 and len(stream) == len(cat):
        report += "VERIFY: %d/%d bytes MATCH — BYTE-EXACT\n" % (n, n)
        return True, report
    report += "VERIFY: %d/%d match, %d mismatches, first at 0x%x; len %s\n" % (
        n - mism,
        n,
        mism,
        max(first, 0),
        "equal" if len(stream) == len(cat) else f"differ (stream {len(stream)}, dumps {len(cat)})",
    )
    return False, report
