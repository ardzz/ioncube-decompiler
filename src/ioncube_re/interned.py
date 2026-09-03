"""Interned-name resolution (benchmark gap #1, BENCHMARK-DECODEPHP.md §9).

Wire zvals with negative pool offsets reference the loader's interned-name
cache: ``pooloff = -N`` resolves to ``dummy_int2[N]``, a lazily-decoded cache
over the loader's static dfloat2 dictionary (Hhg 0x407a5). The full table is
statically extractable from the loader's .data and live-verified
(notes/INTERNED.md — 591 static entries + the -1/-2 dynamic specials,
byte-identical across the 8.1/8.2/8.4 loaders); it lives in
``interned_data.py``.

Resolution policy:
  - static entries require the wire len to equal len(name) (it always does —
    a mismatch would indicate a different loader build, so we fall back to
    the placeholder rather than guess);
  - the dynamic specials (-1 = __FILE__, -2 = __DIR__) resolve regardless of
    the len field (the wire len carries the encode-time path length);
  - indices beyond the table (the cache is 600 slots) keep the
    ``/*interned-N len=L*/`` placeholder — never a guess.
"""

from .interned_data import INTERNED_DYNAMIC, INTERNED_STATIC

CONSTANT_TOKENS = frozenset({"__FILE__", "__DIR__", "__LINE__", "__FUNCTION__",
                             "__CLASS__", "__METHOD__", "__NAMESPACE__"})

TABLE_MAX = max(INTERNED_STATIC)


def interned_name(index: int, length: int) -> str | None:
    if index in INTERNED_DYNAMIC:
        return INTERNED_DYNAMIC[index]
    name = INTERNED_STATIC.get(index)
    if name is None:
        return None
    if length != len(name):
        return None  # a different table build — do not guess
    return name


def render_placeholder(index: int, length: int) -> str:
    return f"/*interned-{index} len={length}*/"
