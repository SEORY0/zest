# Zest operation reference

Generated from the registry — 103 operations across 10 categories.
Do not edit by hand; run `npm run docs` instead.

> **Keys in these examples are published test vectors**, quoted from the RFC or NIST document
> that defines each algorithm, so the output can be checked against it. They are not secrets
> and the literal form is only used here to make the vector visible.
>
> Never write a real key, password or token into an argument: argv is readable by any process
> through `ps` and is saved to shell history. Read it with `env:NAME` or `file:PATH` instead —
> `zest hmac:key=env:SIGNING_SECRET` — or `--input-env NAME` when the input itself is secret.

## Contents

- **Encoding** — `to-base64`, `from-base64`, `to-base32`, `from-base32`, `to-base58`, `from-base58`, `to-base85`, `from-base85`, `to-hex`, `from-hex`, `url-encode`, `url-decode`, `to-html-entity`, `from-html-entity`, `to-charcode`, `from-charcode`, `to-binary`, `from-binary`, `to-decimal`, `from-decimal`, `to-quoted-printable`, `from-quoted-printable`, `to-morse`, `from-morse`, `to-latin1`
- **Hashing** — `md5`, `sha1`, `sha2`, `sha3`, `keccak`, `hmac`, `crc32`, `adler32`, `pbkdf2`
- **Encryption** — `aes-encrypt`, `aes-decrypt`, `xor`, `xor-brute-force`, `rot`, `rot47`, `vigenere-encode`, `vigenere-decode`, `rc4`, `bitwise-not`, `bit-rotate`, `derive-aes-key`, `random-key`
- **Text** — `change-case`, `reverse`, `sort-lines`, `unique-lines`, `filter-lines`, `find-replace`, `regex-extract`, `split-join`, `remove-whitespace`, `trim-lines`, `head-tail`, `pad-lines`, `count`, `escape-string`, `unescape-string`
- **Data** — `json-format`, `json-minify`, `json-path`, `csv-to-json`, `json-to-csv`, `jwt-decode`, `jwt-verify`, `parse-query-string`, `to-query-string`, `xml-format`
- **Compression** — `gzip`, `gunzip`
- **Network** — `defang`, `fang`, `ip-to-int`, `int-to-ip`, `parse-cidr`, `parse-uri`, `extract-indicators`
- **Analysis** — `hexdump`, `from-hexdump`, `entropy`, `frequency`, `detect-file-type`, `strings`, `analyse-hash`, `take-bytes`, `drop-bytes`, `to-table`, `to-raw`, `magic`
- **Date & time** — `unix-to-date`, `date-to-unix`, `filetime-to-date`, `now`, `shift-time`
- **Generate** — `generate-uuid`, `generate-random`, `generate-password`, `generate-totp`, `repeat`

## Encoding

### `to-base64`

**To Base64** — Encodes bytes as Base64 text. Use the URL-safe alphabet for values that travel in query strings or JWTs.

_Also known as: b64, rfc4648._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `alphabet` | select: Standard \| URL-safe \| Custom | `Standard` | — |
| `custom` | string | — | 64 characters, used when alphabet is Custom |
| `padding` | boolean | `true` | Append = so the output length is a multiple of 4 |

**Examples**

```console
$ zest -i "Hello, world!" to-base64
SGVsbG8sIHdvcmxkIQ==
```

_URL-safe, unpadded_
```console
$ zest -i "ÿï¾" to-base64:alphabet=URL-safe,padding=false
w7_Dr8K-
```

### `from-base64`

**From Base64** — Decodes Base64 text back to bytes. Whitespace and missing padding are tolerated; set strict to reject anything outside the alphabet.

_Also known as: b64, decode, rfc4648._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `alphabet` | select: Standard \| URL-safe \| Custom | `Standard` | — |
| `custom` | string | — | — |
| `strict` | boolean | `false` | Fail on characters outside the alphabet instead of skipping them |

**Examples**

```console
$ zest -i "SGVsbG8sIHdvcmxkIQ==" from-base64
Hello, world!
```

_Tolerates newlines_
```console
$ zest -i "SGVs\nbG8=" from-base64
Hello
```

### `to-base32`

**To Base32** — Encodes bytes as Base32 (RFC 4648). Common in TOTP seeds and case-insensitive identifiers.

_Also known as: totp, otp, rfc4648._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `alphabet` | select: RFC 4648 \| base32hex | `RFC 4648` | — |
| `padding` | boolean | `true` | — |

**Examples**

```console
$ zest -i "Hello" to-base32
JBSWY3DP
```

### `from-base32`

**From Base32** — Decodes Base32 text back to bytes.

_Also known as: totp, otp._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `alphabet` | select: RFC 4648 \| base32hex | `RFC 4648` | — |

**Examples**

```console
$ zest -i "JBSWY3DP" from-base32
Hello
```

### `to-base58`

**To Base58** — Encodes bytes as Base58. The Bitcoin alphabet omits 0, O, I and l so encoded values survive being read aloud or retyped.

_Also known as: bitcoin, btc, ipfs, wallet._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `alphabet` | select: Bitcoin \| Ripple | `Bitcoin` | — |

**Examples**

```console
$ zest -i "Hello World!" to-base58
2NEpo7TZRRrLZSi2U
```

### `from-base58`

**From Base58** — Decodes Base58 text back to bytes.

_Also known as: bitcoin, btc, ipfs, wallet._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `alphabet` | select: Bitcoin \| Ripple | `Bitcoin` | — |

**Examples**

```console
$ zest -i "2NEpo7TZRRrLZSi2U" from-base58
Hello World!
```

### `to-base85`

**To Base85** — Encodes bytes as Ascii85. Denser than Base64 — four bytes become five characters. Used by PDF and PostScript.

_Also known as: ascii85, a85, pdf, postscript._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `markers` | boolean | `false` | — |

**Examples**

```console
$ zest -i "Hello, world!" to-base85
87cURD_*#TDfTZ)+T
```

### `from-base85`

**From Base85** — Decodes Ascii85 text back to bytes.

_Also known as: ascii85, a85, pdf._

_No arguments._

**Examples**

```console
$ zest -i "87cURD_*#TDfTZ)+T" from-base85
Hello, world!
```

### `to-hex`

**To Hex** — Renders each byte as two hexadecimal digits.

_Also known as: hexadecimal, base16._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `separator` | select: Space \| None \| Comma \| Semi-colon \| Colon \| Line feed \| CRLF | `Space` | — |
| `prefix` | select: None \| 0x \| \x | `None` | — |
| `uppercase` | boolean | `false` | — |

**Examples**

```console
$ zest -i "Hello" to-hex
48 65 6c 6c 6f
```

_C-style literal_
```console
$ zest -i "Hi" to-hex:separator=None,prefix=\x
\x48\x69
```

### `from-hex`

**From Hex** — Parses hexadecimal digits back to bytes, ignoring whitespace, 0x prefixes and any punctuation used as a separator.

_Also known as: hexadecimal, base16, unhex._

_No arguments._

**Examples**

```console
$ zest -i "48 65 6c 6c 6f" from-hex
Hello
```

_Mixed separators_
```console
$ zest -i "0x48,0x69" from-hex
Hi
```

### `url-encode`

**URL encode** — Percent-encodes text for use in a URL. Encode all characters when the value goes in a query string that may be parsed twice.

_Also known as: percent, uri, urlencode._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `encodeAll` | boolean | `false` | — |

**Examples**

```console
$ zest -i "a b&c=d" url-encode
a%20b%26c%3Dd
```

_Leave reserved characters alone_
```console
$ zest -i "https://a.test/x y" url-encode:encodeAll=false
https://a.test/x%20y
```

### `url-decode`

**URL decode** — Decodes percent-encoded text. Decodes + as a space when the input came from a form body.

_Also known as: percent, uri, urldecode._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `plusIsSpace` | boolean | `false` | — |

**Examples**

```console
$ zest -i "a%20b%26c%3Dd" url-decode
a b&c=d
```

_Form encoding_
```console
$ zest -i "a+b" url-decode:plusIsSpace=true
a b
```

### `to-html-entity`

**To HTML entity** — Escapes characters that would otherwise be read as markup. Encode everything when injecting into an attribute of unknown quoting.

_Also known as: escape, xss, htmlencode._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `scope` | select: Special characters \| Everything non-ASCII \| Everything | `Special characters` | — |
| `format` | select: Named where possible \| Decimal \| Hex | `Named where possible` | — |

**Examples**

```console
$ zest -i "<script>alert(1)</script>" to-html-entity
&lt;script&gt;alert(1)&lt;/script&gt;
```

_Hex numeric_
```console
$ zest -i "<a>" to-html-entity:format=Hex
&#x3c;a&#x3e;
```

### `from-html-entity`

**From HTML entity** — Resolves named and numeric HTML entities back to characters.

_Also known as: unescape, htmldecode._

_No arguments._

**Examples**

```console
$ zest -i "&lt;b&gt;hi&lt;/b&gt; &amp; &#x263A;" from-html-entity
<b>hi</b> & ☺
```

### `to-charcode`

**To character code** — Writes each byte as a number in the base you choose.

_Also known as: ord, ascii, octal._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `base` | select: Binary \| Octal \| Decimal \| Hexadecimal | `Hexadecimal` | — |
| `separator` | select: Space \| None \| Comma \| Semi-colon \| Colon \| Line feed \| CRLF | `Space` | — |

**Examples**

```console
$ zest -i "Hi" to-charcode:base=Decimal
72 105
```

### `from-charcode`

**From character code** — Parses a list of numbers back to bytes. Any non-digit run counts as a separator.

_Also known as: chr, ascii, octal._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `base` | select: Binary \| Octal \| Decimal \| Hexadecimal | `Hexadecimal` | — |

**Examples**

```console
$ zest -i "72 105" from-charcode:base=Decimal
Hi
```

### `to-binary`

**To binary** — Writes each byte as eight bits.

_Also known as: bits, base2._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `separator` | select: Space \| None \| Comma \| Semi-colon \| Colon \| Line feed \| CRLF | `Space` | — |

**Examples**

```console
$ zest -i "Hi" to-binary
01001000 01101001
```

### `from-binary`

**From binary** — Parses a run of bits back to bytes.

_Also known as: bits, base2._

_No arguments._

**Examples**

```console
$ zest -i "01001000 01101001" from-binary
Hi
```

### `to-decimal`

**To decimal** — Writes each byte as a decimal number.

_Also known as: base10, ord._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `separator` | select: Space \| None \| Comma \| Semi-colon \| Colon \| Line feed \| CRLF | `Space` | — |

**Examples**

```console
$ zest -i "Hi" to-decimal
72 105
```

### `from-decimal`

**From decimal** — Parses decimal numbers back to bytes.

_Also known as: base10, chr._

_No arguments._

**Examples**

```console
$ zest -i "72 105" from-decimal
Hi
```

### `to-quoted-printable`

**To quoted-printable** — Encodes bytes for an email body: printable ASCII stays as-is, everything else becomes =XX, and lines wrap at 76 characters.

_Also known as: email, mime, qp._

_No arguments._

**Examples**

```console
$ zest -i "café" to-quoted-printable
caf=C3=A9
```

### `from-quoted-printable`

**From quoted-printable** — Decodes a quoted-printable email body, joining soft line breaks.

_Also known as: email, mime, qp._

_No arguments._

**Examples**

```console
$ zest -i "caf=C3=A9" from-quoted-printable
café
```

### `to-morse`

**To Morse code** — Converts letters, digits and common punctuation to Morse.

_Also known as: cw, telegraph._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `letterSeparator` | string | ` ` | — |
| `wordSeparator` | string | `/` | — |

**Examples**

```console
$ zest -i "SOS" to-morse
... --- ...
```

### `from-morse`

**From Morse code** — Decodes Morse back to text. Accepts dots and dashes in any spacing, with / between words.

_Also known as: cw, telegraph._

_No arguments._

**Examples**

```console
$ zest -i "... --- ..." from-morse
SOS
```

### `to-latin1`

**Repair UTF-8 mojibake** — Treats the input text code points as Latin-1 bytes, repairing UTF-8 text that was previously decoded with the wrong charset.

_Also known as: mojibake, iso-8859-1, charset, encoding._

_No arguments._

**Examples**

_Repair UTF-8 decoded as Latin-1_
```console
$ zest -i "cafÃ©" to-latin1
café
```

## Hashing

### `md5`

**MD5** — MD5 digest. Broken for signatures since 2004 — treat a match as an integrity check, never as proof of authenticity.

_Also known as: digest, checksum._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `format` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

**Examples**

```console
$ zest -i "hello" md5
5d41402abc4b2a76b9719d911017c592
```

### `sha1`

**SHA-1** — SHA-1 digest. Collisions are practical (SHAttered, 2017); still seen in Git object IDs and legacy TLS.

_Also known as: digest, git._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `format` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

**Examples**

```console
$ zest -i "hello" sha1
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
```

### `sha2`

**SHA-2** — SHA-2 digest at the size you choose. The default for anything that needs to stay trustworthy.

_Also known as: sha256, sha512, sha384, digest._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `size` | select: SHA-256 \| SHA-384 \| SHA-512 | `SHA-256` | — |
| `format` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

**Examples**

```console
$ zest -i "hello" sha2
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

_SHA-512_
```console
$ zest -i "hello" sha2:size=SHA-512
9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
```

### `sha3`

**SHA-3** — SHA-3 digest (FIPS 202). A sponge construction, so it is immune to the length-extension attacks SHA-2 allows.

_Also known as: keccak, fips202, digest._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `size` | select: 224 \| 256 \| 384 \| 512 | `256` | — |
| `format` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

**Examples**

```console
$ zest -i "" sha3
a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
```

### `keccak`

**Keccak** — Original Keccak digest, with the pre-standard 0x01 padding. This is what Ethereum means by "sha3".

_Also known as: ethereum, evm, solidity, sha3._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `size` | select: 224 \| 256 \| 384 \| 512 | `256` | — |
| `format` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

**Examples**

```console
$ zest -i "" keccak
c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
```

### `hmac`

**HMAC** — Keyed hash for message authentication. Unlike a bare hash, an attacker cannot recompute it without the key.

_Also known as: mac, signature, authentication._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `key` | key | — | — |
| `algorithm` | select: SHA-256 \| SHA-384 \| SHA-512 \| SHA-1 \| MD5 | `SHA-256` | — |
| `format` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

**Examples**

_RFC 4231 test case 1_
```console
$ zest -i "Hi There" hmac:key=hex:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b,algorithm=SHA-256
b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
```

### `crc32`

**CRC-32** — CRC-32 checksum (IEEE 802.3, the ZIP and PNG polynomial). Detects accidental corruption; trivially forged on purpose.

_Also known as: checksum, zip, png._

_No arguments._

**Examples**

```console
$ zest -i "hello" crc32
3610a686
```

### `adler32`

**Adler-32** — Adler-32 checksum. Faster than CRC-32 and used by zlib, but weak on short inputs.

_Also known as: checksum, zlib._

_No arguments._

**Examples**

```console
$ zest -i "hello" adler32
062c0215
```

### `pbkdf2`

**PBKDF2** — Derives a key from a password by iterating a hash. Raise the iteration count until derivation takes ~100ms on your slowest client.

_Also known as: kdf, password, derive, rfc2898._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `salt` | key | — | — |
| `iterations` | number | `100000` | range 1…∞ |
| `keyLength` | number | `256` | range 8…∞ |
| `hash` | select: SHA-256 \| SHA-384 \| SHA-512 \| SHA-1 | `SHA-256` | — |
| `format` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

**Examples**

_RFC 6070 test case 1 (SHA-1)_
```console
$ zest -i "password" pbkdf2:salt=salt,iterations=1,keyLength=160,hash=SHA-1
0c60c80f961f0e71f3a9b524af6012062fe037a6
```

## Encryption

### `aes-encrypt`

**AES encrypt** — Encrypts with AES. GCM also authenticates the ciphertext and appends a tag — prefer it unless a format forces CBC or CTR on you.

_Also known as: rijndael, gcm, cbc, ctr, symmetric._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `key` | key | — | — |
| `iv` | key | — | 16 bytes for CBC and CTR, 12 for GCM |
| `mode` | select: GCM \| CBC \| CTR | `GCM` | — |
| `aad` | key | — | — |
| `tagLength` | number | `128` | — |
| `output` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

**Examples**

_AES-128-CBC_
```console
$ zest -i "Attack at dawn!!" aes-encrypt:key=hex:000102030405060708090a0b0c0d0e0f,iv=hex:000102030405060708090a0b0c0d0e0f,mode=CBC
90a38387d67662f6663d529f748e0b5a191169e48f69ddebbe4412196196bc98
```

### `aes-decrypt`

**AES decrypt** — Decrypts AES ciphertext. For GCM the authentication tag must be the last 16 bytes of the input; a wrong key and a tampered message both fail the same way.

_Also known as: rijndael, gcm, cbc, ctr, symmetric._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `key` | key | — | — |
| `iv` | key | — | — |
| `mode` | select: GCM \| CBC \| CTR | `GCM` | — |
| `aad` | key | — | — |
| `tagLength` | number | `128` | — |
| `input` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

### `xor`

**XOR** — XORs the input against a repeating key. Symmetric — running it twice with the same key returns the original.

_Also known as: obfuscation, malware, ctf._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `key` | key | — | — |
| `output` | select: Hex \| Base64 \| Raw bytes | `Raw bytes` | — |

**Examples**

_Single-byte key_
```console
$ zest -i "Hello" xor:key=hex:41,output=Hex
09242d2d2e
```

### `xor-brute-force`

**XOR brute force** — Tries every single-byte XOR key and reports the ones that produce printable text. The starting point for most obfuscated blobs.

_Also known as: crack, ctf, malware, bruteforce._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `crib` | string | — | Only show keys whose output contains this text |
| `printableOnly` | boolean | `true` | — |
| `sampleLength` | number | `80` | range 8…∞ |

**Examples**

_Recovers key 0x41_
```console
$ zest -i "09242d2d2e" xor-brute-force:crib=Hello
key=0x41  Hello
```

### `rot`

**ROT** — Rotates letters through the alphabet. ROT13 is its own inverse. A puzzle, not a cipher.

_Also known as: rot13, caesar, shift._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `amount` | number | `13` | range -25…25 |

**Examples**

```console
$ zest -i "Hello, World!" rot
Uryyb, Jbeyq!
```

_Caesar shift of 3_
```console
$ zest -i "attack" rot:amount=3
dwwdfn
```

### `rot47`

**ROT47** — Rotates every printable ASCII character, not just letters, so digits and punctuation change too. Self-inverse at the default of 47.

_Also known as: rot, shift, ctf._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `amount` | number | `47` | range -94…94 |

**Examples**

```console
$ zest -i "Hello, World!" rot47
w6==@[ (@C=5P
```

### `vigenere-encode`

**Vigenère encode** — Polyalphabetic substitution using a repeating keyword. Broken by frequency analysis once you know the key length.

_Also known as: classical, ctf, polyalphabetic._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `key` | string | — | — |

**Examples**

```console
$ zest -i "attackatdawn" vigenere-encode:key=lemon
lxfopvefrnhr
```

### `vigenere-decode`

**Vigenère decode** — Reverses a Vigenère encoding with a known keyword.

_Also known as: classical, ctf, polyalphabetic._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `key` | string | — | — |

**Examples**

```console
$ zest -i "lxfopvefrnhr" vigenere-decode:key=lemon
attackatdawn
```

### `rc4`

**RC4** — RC4 stream cipher. Symmetric, and prohibited in TLS since RFC 7465 — you will meet it in malware and old protocols, not in anything you should build.

_Also known as: arcfour, stream, malware._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `key` | key | — | — |
| `output` | select: Hex \| Base64 \| Raw bytes | `Raw bytes` | — |

**Examples**

_RFC 6229 40-bit key_
```console
$ zest -i "Plaintext" rc4:key=Key,output=Hex
bbf316e8d940af0ad3
```

### `bitwise-not`

**Bitwise NOT** — Inverts every bit. A common one-step obfuscation in packed binaries.

_Also known as: invert, complement, malware._

_No arguments._

### `bit-rotate`

**Bit rotate** — Rotates the bits of each byte left or right. Pairs with XOR in simple packers.

_Also known as: rol, ror, shift, malware._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `direction` | select: Left \| Right | `Left` | — |
| `amount` | number | `1` | range 0…7 |

**Examples**

```console
$ zest -i "A" bit-rotate:amount=1

```

### `derive-aes-key`

**Derive AES key from password** — Turns a password into an AES key with PBKDF2. Use this rather than hashing a password once — the iteration count is what makes brute force expensive.

_Also known as: pbkdf2, kdf, password._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `salt` | key | — | — |
| `iterations` | number | `600000` | range 1…∞ |
| `keySize` | select: 128 \| 192 \| 256 | `256` | — |
| `hash` | select: SHA-256 \| SHA-512 | `SHA-256` | — |
| `output` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

### `random-key`

**Generate AES key and IV** — Emits a fresh key and nonce from the system CSPRNG, ready to paste into AES encrypt.

_Also known as: keygen, csprng, nonce._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `keySize` | select: 128 \| 192 \| 256 | `256` | — |
| `ivLength` | number | `12` | range 1…32 |

## Text

### `change-case`

**Change case** — Converts text between the common casing conventions.

_Also known as: uppercase, lowercase, camel, snake, kebab._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `style` | select: lower \| UPPER \| Title \| Sentence \| camelCase \| snake_case \| kebab-case \| CONSTANT_CASE | `lower` | — |

**Examples**

```console
$ zest -i "Hello World" change-case:style=snake_case
hello_world
```

```console
$ zest -i "user_id_value" change-case:style=camelCase
userIdValue
```

### `reverse`

**Reverse** — Reverses the input by character, line or byte.

_Also known as: flip, mirror._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `by` | select: Character \| Line \| Byte | `Character` | — |

**Examples**

```console
$ zest -i "abc\ndef" reverse:by=Line
def
abc
```

### `sort-lines`

**Sort lines** — Sorts lines alphabetically, numerically or by length.

_Also known as: order, alphabetical._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `order` | select: Alphabetical \| Numeric \| Length \| IP address | `Alphabetical` | — |
| `reverse` | boolean | `false` | — |
| `caseSensitive` | boolean | `false` | — |

**Examples**

```console
$ zest -i "banana\napple\ncherry" sort-lines
apple
banana
cherry
```

### `unique-lines`

**Unique lines** — Removes duplicate lines, keeping the first occurrence of each.

_Also known as: dedupe, distinct, uniq._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `caseSensitive` | boolean | `true` | — |
| `showCounts` | boolean | `false` | — |

**Examples**

```console
$ zest -i "a\nb\na\nc" unique-lines
a
b
c
```

### `filter-lines`

**Filter lines** — Keeps or drops lines matching a pattern. The workhorse for cutting a log down to the interesting part.

_Also known as: grep, match, search._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `pattern` | string | — | — |
| `literal` | boolean | `false` | — |
| `invert` | boolean | `false` | — |
| `caseSensitive` | boolean | `true` | — |

**Examples**

```console
$ zest -i "error: a\nok: b\nerror: c" filter-lines:pattern=^error
error: a
error: c
```

### `find-replace`

**Find and replace** — Replaces matches of a pattern. Capture groups are available as $1, $2 and so on.

_Also known as: substitute, regex, sed._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `find` | string | — | — |
| `replace` | string | — | — |
| `literal` | boolean | `false` | — |
| `global` | boolean | `true` | — |
| `caseSensitive` | boolean | `true` | — |
| `multiline` | boolean | `true` | — |

**Examples**

```console
$ zest -i "a1b2c3" find-replace:find=[0-9],replace=#
a#b#c#
```

### `regex-extract`

**Regex extract** — Pulls out every match of a pattern, one per line. With a capture group, extracts the group instead of the whole match.

_Also known as: regex, match, scrape, grep -o._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `pattern` | string | — | — |
| `caseSensitive` | boolean | `true` | — |
| `unique` | boolean | `false` | — |

**Examples**

```console
$ zest -i "a@x.test b@y.test" regex-extract:pattern=[\w.]+@[\w.]+
a@x.test
b@y.test
```

### `split-join`

**Split and join** — Re-delimits a list: split on one string, join with another. Use \n and \t for whitespace.

_Also known as: delimiter, csv, implode, explode._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `splitOn` | string | `,` | — |
| `joinWith` | string | `\n` | — |
| `trim` | boolean | `true` | — |
| `dropEmpty` | boolean | `false` | — |

**Examples**

```console
$ zest -i "a, b, c" split-join:splitOn=,,joinWith=|
a|b|c
```

### `remove-whitespace`

**Remove whitespace** — Strips whitespace. Useful before decoding a value that was pretty-printed across lines.

_Also known as: trim, strip, clean._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `spaces` | boolean | `true` | — |
| `lineFeeds` | boolean | `true` | — |
| `tabs` | boolean | `true` | — |
| `carriageReturns` | boolean | `true` | — |

**Examples**

```console
$ zest -i "a b\nc\td" remove-whitespace
abcd
```

### `trim-lines`

**Trim lines** — Removes leading and trailing whitespace from each line.

_Also known as: strip, clean._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `side` | select: Both \| Start \| End | `Both` | — |

**Examples**

```console
$ zest -i "  a  \n  b" trim-lines
a
b
```

### `head-tail`

**Head / tail** — Keeps the first or last N lines.

_Also known as: limit, truncate, first, last._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `end` | select: Head \| Tail | `Head` | — |
| `count` | number | `10` | range 0…∞ |

**Examples**

```console
$ zest -i "a\nb\nc\nd" head-tail:count=2
a
b
```

### `pad-lines`

**Pad lines** — Adds a prefix or suffix to every line. Handy for quoting a list into a SQL IN clause or a shell loop.

_Also known as: prefix, suffix, wrap, quote._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `prefix` | string | — | — |
| `suffix` | string | — | — |
| `skipEmpty` | boolean | `true` | — |

**Examples**

```console
$ zest -i "a\nb" pad-lines:prefix=',suffix=',
'a',
'b',
```

### `count`

**Count** — Reports byte, character, word and line counts.

_Also known as: length, wc, statistics._

_No arguments._

**Examples**

```console
$ zest -i "hello world" count
bytes       11
characters  11
words        2
lines        1
```

### `escape-string`

**Escape string** — Escapes text so it can be pasted into source code as a string literal.

_Also known as: quote, literal, json, python._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `style` | select: JSON \| JavaScript \| Python \| Shell | `JSON` | — |
| `quotes` | boolean | `false` | — |

**Examples**

```console
$ zest -i "a\"b\nc" escape-string
a\"b\nc
```

### `unescape-string`

**Unescape string** — Resolves backslash escapes — \n, \t, \xNN, \uNNNN — back to the characters they stand for.

_Also known as: unquote, literal, json._

_No arguments._

**Examples**

```console
$ zest -i "a\\nb\\x21" unescape-string
a
b!
```

## Data

### `json-format`

**Format JSON** — Re-indents JSON. Sorting keys makes two documents diffable.

_Also known as: pretty, beautify, indent._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `indent` | number | `2` | range 0…8 |
| `sortKeys` | boolean | `false` | — |

**Examples**

```console
$ zest -i "{\"b\":1,\"a\":2}" json-format:indent=2
{
  "b": 1,
  "a": 2
}
```

### `json-minify`

**Minify JSON** — Removes all insignificant whitespace from JSON.

_Also known as: compact, compress._

_No arguments._

**Examples**

```console
$ zest -i "{\n  \"a\": 1\n}" json-minify
{"a":1}
```

### `json-path`

**JSON extract** — Reads a value out of a JSON document with a dotted path. Use [n] for array indices and [*] to map over every element.

_Also known as: jq, jsonpath, query, select._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `path` | string | — | — |
| `raw` | boolean | `true` | — |

**Examples**

```console
$ zest -i "{\"users\":[{\"name\":\"ana\"},{\"name\":\"bo\"}]}" json-path:path=users[*].name
ana
bo
```

### `csv-to-json`

**CSV to JSON** — Parses CSV into an array of objects, honouring quoted fields.

_Also known as: spreadsheet, tabular, convert._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `delimiter` | string | `,` | — |
| `header` | boolean | `true` | — |
| `indent` | number | `2` | range 0…8 |

**Examples**

```console
$ zest -i "a,b\n1,2" csv-to-json:indent=0
[{"a":"1","b":"2"}]
```

### `json-to-csv`

**JSON to CSV** — Flattens an array of objects into CSV. The column set is the union of every object's keys.

_Also known as: spreadsheet, tabular, convert._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `delimiter` | string | `,` | — |
| `header` | boolean | `true` | — |

**Examples**

```console
$ zest -i "[{\"a\":1,\"b\":2}]" json-to-csv
a,b
1,2
```

### `jwt-decode`

**JWT decode** — Splits a JSON Web Token and decodes its header and payload. This does not verify the signature — an unverified token proves nothing.

_Also known as: jsonwebtoken, bearer, token, auth, oauth._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `expandTimes` | boolean | `true` | — |

**Examples**

```console
$ zest -i "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig" jwt-decode:expandTimes=false
header
{
  "alg": "HS256",
  "typ": "JWT"
}

payload
{
  "sub": "123"
}

signature
sig (3 chars, base64url)
```

### `jwt-verify`

**JWT verify (HMAC)** — Checks an HS256/384/512 signature against a shared secret and reports whether it holds.

_Also known as: jsonwebtoken, hs256, signature, auth._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `secret` | key | — | — |

### `parse-query-string`

**Parse query string** — Breaks a query string or form body into key/value pairs, decoding percent escapes.

_Also known as: url, params, form, urlencoded._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `format` | select: Table \| JSON | `Table` | — |

**Examples**

```console
$ zest -i "a=1&b=hello%20world" parse-query-string
a  1
b  hello world
```

### `to-query-string`

**Build query string** — Turns a JSON object into a percent-encoded query string.

_Also known as: url, params, form._

_No arguments._

**Examples**

```console
$ zest -i "{\"a\":1,\"b\":\"hello world\"}" to-query-string
a=1&b=hello%20world
```

### `xml-format`

**Format XML** — Re-indents XML by nesting depth. A formatter, not a validator — it will not tell you the document is malformed.

_Also known as: pretty, beautify, html, indent._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `indent` | number | `2` | range 0…8 |

**Examples**

```console
$ zest -i "<a><b>1</b></a>" xml-format
<a>
  <b>1</b>
</a>
```

## Compression

### `gzip`

**Gzip** — Compresses with gzip. Output is binary — follow with To Base64 or To Hex to make it printable.

_Also known as: compress, deflate, zip._

_Produces binary output; chain `to-base64` or `to-hex` to make it printable._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `format` | select: Gzip \| Zlib (deflate) \| Raw deflate | `Gzip` | — |

### `gunzip`

**Gunzip** — Decompresses gzip, zlib or raw deflate data.

_Also known as: decompress, inflate, unzip._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `format` | select: Gzip \| Zlib (deflate) \| Raw deflate \| Detect | `Detect` | — |

## Network

### `defang`

**Defang indicator** — Neuters URLs, domains and IPs so they will not auto-link or be clicked by accident. The convention for sharing indicators in a report.

_Also known as: ioc, threat, sanitise, sanitize, phishing._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `dots` | boolean | `true` | — |
| `scheme` | boolean | `true` | — |
| `at` | boolean | `true` | — |

**Examples**

```console
$ zest -i "https://evil.test/a" defang
hxxps://evil[.]test/a
```

```console
$ zest -i "user@evil.test" defang
user[@]evil[.]test
```

### `fang`

**Refang indicator** — Reverses defanging so an indicator becomes usable again. Accepts the [.], (.), {.} and hxxp variants.

_Also known as: ioc, threat, restore._

_No arguments._

**Examples**

```console
$ zest -i "hxxps://evil[.]test/a" fang
https://evil.test/a
```

### `ip-to-int`

**IPv4 to integer** — Converts dotted-quad addresses to their 32-bit integer form, one per line.

_Also known as: address, convert, long._

_No arguments._

**Examples**

```console
$ zest -i "192.168.1.1" ip-to-int
3232235777
```

### `int-to-ip`

**Integer to IPv4** — Converts 32-bit integers back to dotted-quad addresses.

_Also known as: address, convert, long._

_No arguments._

**Examples**

```console
$ zest -i "3232235777" int-to-ip
192.168.1.1
```

### `parse-cidr`

**Parse CIDR** — Expands a CIDR block into its network address, broadcast address, mask, host count and scope.

_Also known as: subnet, netmask, range, network._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `listAddresses` | boolean | `false` | — |

**Examples**

```console
$ zest -i "192.168.1.0/24" parse-cidr
network    192.168.1.0
broadcast  192.168.1.255
first host 192.168.1.1
last host  192.168.1.254
netmask    255.255.255.0
wildcard   0.0.0.255
addresses  256
usable     254
scope      private (RFC 1918)
```

### `parse-uri`

**Parse URI** — Breaks a URL into its parts and lists the query parameters separately.

_Also known as: url, components, query, host._

_No arguments._

**Examples**

```console
$ zest -i "https://user:pw@host.test:8443/a/b?x=1&y=2#frag" parse-uri
scheme    https:
username  user
password  pw
host      host.test
port      8443
path      /a/b
query     ?x=1&y=2
fragment  #frag

parameters
  x  1
  y  2
```

### `extract-indicators`

**Extract indicators** — Pulls URLs, domains, IPs, email addresses and hashes out of unstructured text — a first pass over a log, a phishing mail or a report.

_Also known as: ioc, threat, scrape, hunt._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `kind` | select: All \| URL \| Domain \| IPv4 \| IPv6 \| Email \| Hash | `All` | — |
| `defangInput` | boolean | `true` | — |
| `unique` | boolean | `true` | — |

**Examples**

```console
$ zest -i "contact a@b.test or visit https://x.test from 10.0.0.1" extract-indicators:kind=All
URL
https://x.test

IPv4
10.0.0.1

Email
a@b.test
```

## Analysis

### `hexdump`

**Hex dump** — Renders bytes as a classic offset / hex / ASCII dump.

_Also known as: xxd, hd, dump, binary, view._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `width` | number | `16` | range 4…64 |
| `offset` | number | `0` | — |

**Examples**

```console
$ zest -i "Hello, hex dump!" hexdump
00000000  48 65 6c 6c 6f 2c 20 68  65 78 20 64 75 6d 70 21  |Hello, hex dump!|
```

### `from-hexdump`

**From hex dump** — Recovers the bytes from a hex dump, discarding the offset column and the ASCII gutter.

_Also known as: xxd, undump, parse._

_No arguments._

**Examples**

```console
$ zest -i "00000000  48 65 6c 6c 6f  |Hello|" from-hexdump
Hello
```

### `entropy`

**Entropy** — Shannon entropy in bits per byte. Above ~7.5 means encrypted or compressed; English prose sits near 4.

_Also known as: randomness, packed, encrypted, malware._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `blockSize` | number | `0` | 0 reports the whole input only. range 0…∞ |

**Examples**

```console
$ zest -i "aaaaaaaa" entropy
entropy   0.000 bits per byte
verdict   single repeated byte
```

### `frequency`

**Byte frequency** — Counts how often each byte occurs. The starting point for breaking a substitution cipher.

_Also known as: histogram, distribution, cryptanalysis, statistics._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `top` | number | `16` | range 1…256 |
| `printableOnly` | boolean | `false` | — |

**Examples**

```console
$ zest -i "aab" frequency:top=2
'a' 0x61     2   66.7%  ████████████████████
'b' 0x62     1   33.3%  ██████████
```

### `detect-file-type`

**Detect file type** — Identifies the format from its magic bytes. Reports every signature that matches, since containers overlap.

_Also known as: magic, signature, mime, identify, file._

_No arguments._

**Examples**

_PNG header_
```console
$ zest -i "89504e470d0a1a0a" --in-encoding hex detect-file-type
PNG
extension  .png
mime       image/png
matched    8 bytes at offset 0
```

### `strings`

**Extract strings** — Pulls printable runs out of a binary, the way strings(1) does. Finds URLs, paths and error messages in a sample.

_Also known as: binary, malware, triage, ascii, unicode._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `minLength` | number | `4` | range 1…∞ |
| `encoding` | select: ASCII \| UTF-16LE \| Both | `Both` | — |
| `showOffsets` | boolean | `false` | — |

**Examples**

_Finds the readable run_
```console
$ zest -i "00006865782d68657265ff" --in-encoding hex strings:minLength=4
hex-here
```

### `analyse-hash`

**Identify hash** — Guesses what produced a hash from its length, alphabet and prefix. A shortlist, not an answer — many algorithms share a digest size.

_Also known as: hashid, identify, cracking, hashcat._

_No arguments._

**Examples**

```console
$ zest -i "5d41402abc4b2a76b9719d911017c592" analyse-hash
32 hex characters (128 bits)

candidates
  MD5
  MD4
  NTLM
  LM (half)
```

### `take-bytes`

**Take bytes** — Keeps a slice of the input. Negative offsets count from the end.

_Also known as: slice, substring, cut, head, dd._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `start` | number | `0` | — |
| `length` | number | `0` | 0 takes everything from start onwards |

**Examples**

```console
$ zest -i "Hello, world" take-bytes:start=7,length=5
world
```

### `drop-bytes`

**Drop bytes** — Removes a slice from the input — the inverse of Take bytes. Useful for stripping a header before decoding a payload.

_Also known as: slice, remove, strip, header._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `start` | number | `0` | — |
| `length` | number | `1` | range 0…∞ |

**Examples**

```console
$ zest -i "XXHello" drop-bytes:start=0,length=2
Hello
```

### `to-table`

**To table** — Aligns delimited text into fixed-width columns so it can be read without a spreadsheet.

_Also known as: align, columns, format, csv, tsv._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `delimiter` | select: Comma \| Tab \| Pipe \| Semi-colon | `Comma` | — |
| `header` | boolean | `true` | — |

**Examples**

```console
$ zest -i "name,id\nana,1\nbo,22" to-table
name  id
────  ──
ana   1
bo    22
```

### `to-raw`

**Show raw bytes** — Reinterprets the data as Latin-1 so every byte becomes one visible character. Nothing is lost, unlike a UTF-8 decode of binary data.

_Also known as: binary, latin1, view._

_No arguments._

**Examples**

```console
$ zest -i "48ff" --in-encoding hex to-raw
Hÿ
```

### `magic`

**Magic** — Ranks a bounded set of plausible local decodings. Use it to form hypotheses when you do not know what you are holding.

_Also known as: detect, auto, identify, decode, guess, unknown._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `depth` | number | `3` | range 1…4 |
| `crib` | string | — | Only show results containing this text |
| `intensive` | boolean | `false` | — |

## Date & time

### `unix-to-date`

**Unix timestamp to date** — Converts an epoch timestamp to a readable UTC date, in whichever unit the value uses.

_Also known as: epoch, timestamp, convert._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `unit` | select: Seconds \| Milliseconds \| Microseconds \| Nanoseconds \| Detect | `Detect` | — |

**Examples**

```console
$ zest -i "1700000000" unix-to-date:unit=Seconds
iso 8601   2023-11-14T22:13:20.000Z
utc        Tue, 14 Nov 2023 22:13:20 GMT
unix (s)   1700000000
unix (ms)  1700000000000
```

### `date-to-unix`

**Date to Unix timestamp** — Parses a date string and reports it as an epoch timestamp. Input without a timezone is read as UTC.

_Also known as: epoch, timestamp, parse._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `unit` | select: Seconds \| Milliseconds \| Microseconds \| Nanoseconds | `Seconds` | — |

**Examples**

```console
$ zest -i "2023-11-14T22:13:20Z" date-to-unix
1700000000
```

### `filetime-to-date`

**Windows FILETIME to date** — Converts a Windows FILETIME (100-nanosecond ticks since 1601) to a UTC date. Found throughout the registry and event logs.

_Also known as: windows, registry, forensics, evtx._

_No arguments._

**Examples**

```console
$ zest -i "133445222400000000" filetime-to-date
iso 8601   2023-11-15T11:44:00.000Z
```

### `now`

**Current time** — Emits the current time in every common representation. Ignores its input.

_Also known as: date, timestamp, epoch._

_No arguments._

### `shift-time`

**Shift time** — Adds or subtracts an interval from a date. Negative values move backwards.

_Also known as: offset, add, subtract, delta._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `days` | number | `0` | — |
| `hours` | number | `0` | — |
| `minutes` | number | `0` | — |
| `seconds` | number | `0` | — |

**Examples**

```console
$ zest -i "2023-11-14T22:13:20Z" shift-time:hours=2
2023-11-15T00:13:20.000Z
```

## Generate

### `generate-uuid`

**Generate UUID** — Emits random version 4 UUIDs. Ignores its input.

_Also known as: guid, uuid4, random, identifier._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `count` | number | `1` | range 1…10000 |
| `uppercase` | boolean | `false` | — |
| `braces` | boolean | `false` | — |

### `generate-random`

**Generate random bytes** — Emits cryptographically secure random bytes. Ignores its input.

_Also known as: entropy, nonce, iv, salt, csprng._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `length` | number | `32` | range 1…1048576 |
| `format` | select: Hex \| Base64 \| Raw bytes | `Hex` | — |

### `generate-password`

**Generate password** — Builds passwords from a character set you choose, and reports how much entropy each one actually carries. Ignores its input.

_Also known as: passphrase, secret, credential, entropy._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `length` | number | `20` | range 4…256 |
| `count` | number | `5` | range 1…1000 |
| `lowercase` | boolean | `true` | — |
| `uppercase` | boolean | `true` | — |
| `digits` | boolean | `true` | — |
| `symbols` | boolean | `true` | — |
| `unambiguous` | boolean | `false` | — |

### `generate-totp`

**Generate TOTP** — Derives the current time-based one-time password from a Base32 secret (RFC 6238). The input is the secret.

_Also known as: 2fa, mfa, otp, authenticator, rfc6238._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `digits` | number | `6` | range 6…10 |
| `period` | number | `30` | range 1…∞ |
| `algorithm` | select: SHA-1 \| SHA-256 \| SHA-512 | `SHA-1` | — |
| `at` | number | `0` | 0 uses the current time |

**Examples**

_RFC 6238 vector at t=59_
```console
$ zest -i "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" generate-totp:at=59,digits=8
94287082
```

### `repeat`

**Repeat** — Repeats the input a number of times. Useful for building buffer-overflow padding and load-test payloads.

_Also known as: pad, fill, buffer, fuzz._

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `count` | number | `2` | range 0…1000000 |
| `separator` | string | — | — |

**Examples**

```console
$ zest -i "ab" repeat:count=3
ababab
```

