"""FUN_00141398 escape codec (escdec) — 24-byte header / adler fields.

Rules: b != 0xFF -> b; "FF xx" with xx < 0x80 -> 0xFF; "FF xx" with xx >= 0x80
-> 0x3C. Byte-exact port of ic_decrypt.php escdec(). Returns (out, new_pos).
"""

ESC_FF = 0xFF
ESC_LT = 0x3C


def escdec(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    out = bytearray()
    i = pos
    lim = len(buf)
    while len(out) < n:
        if i >= lim:
            raise ValueError(f"escdec: input exhausted before {n} outputs")
        b = buf[i]
        if b == 0xFF:
            if i + 1 >= lim:
                raise ValueError("escdec: dangling 0xff")
            out.append(ESC_LT if (buf[i + 1] & 0x80) else ESC_FF)
            i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out), i
