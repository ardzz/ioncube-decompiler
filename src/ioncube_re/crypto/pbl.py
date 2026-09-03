"""pbl container decompressor (FUN_0014575a / 0x44e90).

2-byte control (b0, b1):
  b0 & 0x80 -> b1 literal bytes follow (+ a 0x3c literal when b0 & 0x40);
               the literal run is consumed only when it fully fits the
               remaining output (loader behavior);
  b0 < 0x80 -> 227-byte raw block (only when >= 227 remain; else the loop
               exits).
Byte-exact port of ic_decrypt.php pbl_decode(). Returns (out, new_pos).
"""


def pbl_decode(data: bytes, pos: int, length: int) -> tuple[bytes, int]:
    out = bytearray()
    n = len(data)
    while len(out) < length:
        if pos + 2 > n:
            raise ValueError("pbl: control pair out of range")
        b0 = data[pos]
        b1 = data[pos + 1]
        pos += 2
        if b0 & 0x80:
            if b1 != 0 and length - len(out) >= b1:
                if pos + b1 > n:
                    raise ValueError("pbl: literal run out of range")
                out += data[pos:pos + b1]
                pos += b1
            if b0 & 0x40:
                out.append(0x3C)
        else:
            if length - len(out) >= 0xE3:
                if pos + 0xE3 > n:
                    raise ValueError("pbl: raw block out of range")
                out += data[pos:pos + 0xE3]
                pos += 0xE3
            else:
                break  # loader exits the loop when < 227 remain
    if len(out) != length:
        raise ValueError(f"pbl: produced {len(out)} of {length} bytes")
    return bytes(out), pos
