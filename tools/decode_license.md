# Decoding ionCube license files

A license file created by ionCube's `make_license` normally prints with:

```sh
make_license_64 --decode-license license.txt --passphrase '<passphrase>'
```
You can download `make_license_64` from Ioncube, using the evaluation
package. 

Some licenses additionally bind the decryption key to a 32-bit value that the
encoded application carries in its license probe. `make_license` has no option
for that value and passes 0, so the command above reports the (incorrect) error

```
Unable to decode license file. Either the passphrase is invalid or the license file is corrupt.
```

even when the passphrase is correct.

`decode_license.sh` supplies the value at runtime; this note explains how to
recover both missing pieces.

## License file format (background)

- A `------ LICENSE FILE DATA -------` marker followed by a custom-base64
  block.
- Anything before and after that block is ignored
- The block decodes to `ICLF`, two version bytes, and an encrypted body. The
  body decrypts to `ICLD`, flags, a 32-byte digest, and length-prefixed
  property records (property names and values are XORed with the repeating
  bytes of `0xe9fc23b1`).
- `make_license` derives the cipher key as:

  ```
  passphrase || 02 07 1c 11 || <key32, little-endian> ||
  0a 04 00 39 0f 01 38 00 38 01 00
  ```

## Recover the passphrase from an encoded file

The ionCube encoder embeds the license probe (the license path, the
passphrase, and the error callback) in the encoded container. The probe is
not visible in `strings` of the encoded file because the container is
encrypted, but the container layer is reversible with the decoder in
`tools`:

```sh
ioncube-re decrypt /path/to/Encoded.php
# writes decrypted.Encoded.mainblob.bin and decrypted.Encoded.cipher.bin
strings -a decrypted.Encoded.mainblob.bin
```

The plaintext mainblob contains the probe, for example:

```
/path/to/license.txt
<passphrase>
callback.php
ioncube_event_handler
```

The passphrase is the string between the license path and the callback/handler
fields. The fields around it are 32-bit little-endian length prefixes, so the
list is easiest to read with `strings` or by parsing the mainblob directly.

Programmatically:

```python
import sys
sys.path.insert(0, "ioncube-decompiler/src")
from ioncube_re.container import decrypt_file

plain = decrypt_file("/path/to/Encoded.php")["plain"]
```

Notes:

- License-bound (dynamic-key) files store a decoy keytable mask in the main
  blob, but the license probe itself is still readable at the container layer.
- Multi-version `ICB0` files contain one container per PHP version. Decode the
  chunk the target loader uses (`prod_chunks` in `ioncube_re.container`); the
  probe is the same across chunks.

## Recover the 32-bit key value from the loader

The loader reads the value from the same license probe and passes it as the
4th argument to its license parser. Any encoded file bound to the license
yields the same value (it is a property of the encoded application, not of the
license file).

The exact procedure depends on the loader build. For the loader used here
(13.0.2, `ioncube_loader_lin_8.2.so`, 1,439,016 bytes), the parser entry is at
vaddr `0xf58d0`. Save this as `flag.gdb`:

```gdb
set pagination off
set confirm off
catch load ioncube_loader_lin_8.2.so
run /path/to/Encoded.php
python
import gdb, re
info = gdb.execute('info sharedlibrary ioncube_loader_lin_8.2.so', to_string=True)
m = re.search(r'(0x[0-9a-f]+)\s+0x[0-9a-f]+\s+\S+\s+.*ioncube_loader_lin_8\.2\.so', info)
base = int(m.group(1), 16) - 0x255e0   # gdb reports .text start; subtract its vaddr
gdb.execute('break *%d' % (base + 0xf58d0))
gdb.execute('continue')
end
printf "license:    %s\n", (char*)$rdi
printf "passphrase: %s\n", (char*)$rdx
printf "key32:      0x%x\n", $rcx
continue
```

Run it with:

```sh
gdb -q -batch -x flag.gdb --args php
```

At the parser entry the registers are:

| register | value |
| --- | --- |
| `rdi` | license file path |
| `rsi` | encoded file path |
| `rdx` | passphrase |
| `ecx` | 32-bit key value |

To adapt to another loader build, locate the parser by the key-blob
construction in `.text`: it stores the constant `0x111c0702` (bytes
`02 07 1c 11`) after the passphrase, appends the 32-bit value, then copies the
11-byte constant `0a 04 00 39 0f 01 38 00 38 01 00` from `.rodata`. The
property parser that uses `0xe9fc23b1` sits in the same code path. Adjust the
offset and the base correction for the loader's `.text` vaddr.

## Decode

```sh
ioncube-decompiler/tools/decode_license.sh <license-file> <passphrase> [key32]
```

Examples:

```sh
ioncube-decompiler/tools/decode_license.sh /opt/app/license.txt 'correct horse battery staple'
ioncube-decompiler/tools/decode_license.sh /opt/app/license.txt '<passphrase>' 0x24a88
```

The third argument defaults to 0. Omit it for licenses created by the bundled
`make_license` and supply the value recovered above for licenses that require
one.

The script runs `make_license_64` (get this from ioncube evaluation) under gdb,
sets the value at the decode routine entry (`0x412c80` in the 15.0 build), and
prints the decoded JSON (`expiry`, `properties`, `restrictions`). Use
`MAKE_LICENSE` to point at the location `make_license_64` if not at the default.

## Troubleshooting

- `Unable to decode license file...` — wrong passphrase or wrong `key32` (the
  value is per-license/application, not universal).
- Silent exit 99 — the binary was patched on disk; the evaluation build has an
  integrity check. Use `decode_license.sh`, which changes the register at
  runtime instead.
- gdb cannot place the breakpoint — the `make_license_64` build differs; find
  its decode routine entry from the disassembly (it is the function that
  receives the passphrase and appends the constants above) and update the
  breakpoint address in the script.

## Verification

- Loader-derived mask: for a license-bound encoded file,
  `ioncube-decompiler/tools/extract_license_key.py FILE` reads the mask the loader derived from
  the license's hidden `__mykey` property. When the license decrypts, this
  differs from the decoy mask stored in the file.
- Header consistency: the decoded `expiry` should match the exposed `Expires`
  header line, when present.
