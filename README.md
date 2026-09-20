# ioncube-re

Offline ionCube decompiler. It decrypts encoded files, walks the wire
grammar, and lifts oplines back to readable PHP. Pure stdlib at runtime; the
loader is never executed.

## Quick start

    uv sync
    uv run ioncube-re lift demo/demo-encoded.php

### Example

The `demo/` folder ships the full round trip: `demo/demo-source.php` is the
original source (note the hardcoded HMAC signing key), `demo/demo-encoded.php`
is that file compiled with the ionCube 8.1 evaluation encoder, and
`demo/demo-lifted.php` is what this tool recovers from the encoded file:

```php
$ uv run ioncube-re lift demo/demo-encoded.php
<?php
$issuer = new LicenseIssuer();
$token = $issuer->issue('acme-corp', time());
$issuer->daysLeft($token, time());
printf("token=%s days_left=%d\n", $token); /* no DO_FCALL seen */

class LicenseIssuer
{
    function issue(string $customer, int $now): string
    {
        $stamp = base_convert((string)($now), 10, 36);
        $customer = strtoupper($customer);
        $sig = substr(hash_hmac('sha256', $customer . $stamp, '81518ad9d596db1456828f0391e37436b85af7cac607fc56b203fea292f0f66e6'), 0, 16);
        return $customer . ':' . $stamp . ':' . strtoupper($sig);
    }

    function daysLeft(string $token, int $now): int
    {
        $V8 = explode(':', $token);
        $customer = $V8[0];
        $stamp = $V8[1];
        $sig = $V8[2];
        $issued = (int)(base_convert($stamp, 36, 10));
        $age = intdiv(($now - $issued), 86400);
        $T21 = $age < 0;
        $T21 = (bool)((14 < $age));
        if ($age < 0 || (bool)((14 < $age))) {
            return 0;
        }
        $expect = strtoupper(substr(hash_hmac('sha256', $customer . $stamp, '81518ad9d596db1456828f0391e37436b85af7cac607fc56b203fea292f0f66e6'), 0, 16));
        if (!(hash_equals($expect, $sig))) {
            return 0;
        }
        return 14 - $age;
    }

}
```

The recovered listing passes `php -l`. Typed signatures, constant literals,
and string data come from the wire; `$V*`/`$T*` names mark values the wire
does not name (temporary variables), and the `/* no DO_FCALL seen */` comment
flags a discarded call result the encoder optimized away.

Note what survived decompilation: the "hidden" signing key. ionCube
obfuscation protects code structure, not the data inside it. Keep secrets
server-side.

## Commands

| command | what it does |
|---|---|
| `ioncube-re decrypt FILE [--out P] [--verify REF...]` | eval chain: custom-b64 → escdec K → pbl → adler(a0=17)+MD4-fold verify → X3_(5) keystream → main blob |
| `ioncube-re key FILE...` | decryption key / length / seeds per file |
| `ioncube-re component CIPHER --key eval\|HEX` | layer-B component decrypt (17-byte eval key) |
| `ioncube-re stream decode\|decode-raw\|components\|prod\|verify\|verify-raw` | frame codec + raw DEFLATE; production ICB0 multi-version chunks |
| `ioncube-re wire [--ktab K] [--arena A] [--offline --seeds A,B --ierg 0x.. \| --stream --mainblob B] [--gt GT] FILE...` | wire-grammar walk, node assembly, offline keytable demask, gt cross-check |
| `ioncube-re lift FILE [--chunk N] [--gt GT] [--no-auto] [--m5-dir D] [--valid-php]` | oplines → PHP source (typed signatures, interned names, switch/ternary structuring, opt-in goto-label fallback) |

Exit codes: 0 ok, 1 usage/io, 2 verification/walk failure.

## Supported formats

| what | supported |
|---|---|
| Loader build | 15.5.0 family, PHP 8.1 (`ioncube_loader_lin_8.1.so`) |
| PHP targets | 8.1 (eval-encoded files), 8.1/8.2/8.3/8.4 (production chunks) |
| Containers | "basic" eval container + production ICB0 multi-version |
| Wire grammar | sig mode (v>5) and nosig mode (v≤5), auto-detected |
| Opcode table | PHP 8.1 names (201) |
| Offline keytable | MWC6^ierg formula, validated per file; files whose keytable fails the gate lift wire-only |

## Limitations

- wD0-node opcode recovery for eval v>5 wires falls back to placeholders.
  The production encoder generation leaves the true opcode in the dance
  value, so production files lift fully.
- Files whose offline-keytable validation fails get structure + literals +
  try/catch with per-node placeholders.
- The wire parser does not descend into nested sub-function wires (the
  grammar's [sf] section).
- Interned names resolve from a validated loader-string table; unknown
  indices keep an `/*interned-N len=L*/` placeholder, never a guess.
- Serialized-array zvals recover their string elements only.
- On eval-generation files, a 64-bit long zval whose high word falls outside
  i32 renders from the low word only; true >2^31 integers are the casualty.
  Production files are unaffected.
- Round-trip validity is not a goal: this is a decompiler listing.

## Dependencies

Python ≥ 3.12, managed with uv. The runtime is stdlib-only; dev extras are
pytest (tests) and z3-solver + capstone (declared for research tooling, not
imported by the shipped code).

## License

MIT. See [LICENSE](LICENSE). Use responsibly: this tool exists to recover
source you own or are licensed to maintain, not to bypass license terms. See
[SECURITY.md](SECURITY.md) for the intended-use policy and reporting route.
