# Zest CTF playbooks

These workflows assume the original challenge artifact is preserved. Write outputs
under a fresh working directory and keep command transcripts clear enough to rerun
the winning path.

```bash
zest --version
case_dir="$(mktemp -d)"
cp -- "$ARTIFACT" "$case_dir/original.bin"
```

If the input is a small public challenge string, keep it in a shell variable. If it
is secret or large, put it in a file or environment variable. Public challenge
constants such as a visible AES IV, Vigenere key, or known XOR key may appear
literally in commands; real secrets should use `env:NAME` or `file:PATH`.

For the full operation catalogue, see [operations.md](operations.md).

## General CTF loop

Record context before commands:

```bash
FLAG_RE='^flag\{[ -~]+\}$'     # adapt to the event, e.g. picoCTF\{...\}
CRIB='flag{'                   # use the real known prefix when provided
```

Use the cheapest discriminator that can falsify a hypothesis:

```bash
zest -f "$ARTIFACT" detect-file-type
zest -f "$ARTIFACT" entropy
zest -f "$ARTIFACT" strings:minLength=5,showOffsets=true > "$case_dir/strings.txt"
```

Separate observations from hypotheses in notes:

```text
Observation: detect-file-type reports PNG at offset 128.
Hypothesis: bytes before 128 are a wrapper; carve from offset 128 and inspect.
```

When a candidate flag appears, validate it:

```bash
printf '%s\n' "$CANDIDATE" | grep -E "$FLAG_RE"
# If derived by a reversible recipe, re-encode/decode a small round-trip or rerun the exact chain.
zest -f "$case_dir/original.bin" from-base64 gunzip > "$case_dir/winner.txt"
grep -E "$FLAG_RE" "$case_dir/winner.txt"
```

## Nested encodings and compression

Use `magic` to rank likely chains; provide a crib when a flag prefix is known.

```bash
zest -f challenge.txt magic:depth=4,crib="$CRIB"
zest -f challenge.txt magic:depth=4
```

`magic` can try supported decoders such as Base64, URL-safe Base64, hex, Base32,
Base58, Ascii85, URL decode, HTML entity decode, quoted-printable, binary,
decimal bytes, Morse, gzip, ROT13, ROT47, bitwise NOT, hexadecimal charcodes, JWT
decode, and optional single-byte XOR. It does not try ZIP extraction, PCAP
parsing, stego, RSA solving, password cracking, or unknown repeating-key XOR
recovery.

Rerun the winning recipe explicitly and save the result:

```bash
zest -f challenge.txt from-base64 gunzip -o "$case_dir/decoded.bin"
zest -f "$case_dir/decoded.bin" detect-file-type
zest -f "$case_dir/decoded.bin" strings:minLength=4
```

If the output is structured:

```bash
zest -f challenge.txt from-base64 gunzip json-format -o "$case_dir/decoded.json"
zest -f "$case_dir/decoded.json" json-path:path=flag
```

If `magic` reports nothing useful, inspect entropy and format:

```bash
zest -f challenge.txt entropy
zest -f challenge.txt hexdump | head -40
```

High entropy alone is not proof of encryption; it can also mean compression or
binary data. Do not keep stacking decoders without a shape cue.

## Numeric, charcode, and Morse representations

Try `magic` first for obvious numeric or Morse text:

```bash
zest -f numbers.txt magic:depth=2,crib="$CRIB"
```

If that fails, choose the base by observation:

```bash
zest -f numbers.txt from-decimal
zest -f numbers.txt from-binary
zest -f numbers.txt from-charcode:base=Hexadecimal
zest -f numbers.txt from-charcode:base=Octal
zest -f morse.txt from-morse
```

Validate by readability, exact flag format, or a reverse transform:

```bash
zest -f numbers.txt from-decimal to-decimal
zest -f morse.txt from-morse | grep -E "$FLAG_RE"
```

If values exceed 255, the data is not byte charcodes for Zest. Hand off to a
language/runtime or puzzle-specific parser rather than forcing `from-charcode`.

## XOR

For likely single-byte XOR, prefer a cribbed search:

```bash
zest -f blob.hex xor-brute-force:crib="$CRIB"
zest -f blob.hex xor-brute-force:crib="$CRIB",sampleLength=200
```

Once the key is observed, rerun explicitly:

```bash
zest -f blob.hex from-hex xor:key=hex:41 -o "$case_dir/xor-decoded.bin"
zest -f "$case_dir/xor-decoded.bin" strings:minLength=4
```

For a known repeating XOR key provided by the challenge:

```bash
zest -f cipher.bin xor:key='public-key' -o "$case_dir/xor-known-key.bin"
zest -f "$case_dir/xor-known-key.bin" detect-file-type
```

If the key is unknown and more than one byte, Zest does not recover it. Use
frequency/Kasiski-style tooling or hand off; do not imply `xor-brute-force`
searches repeating keys.

## ROT, Caesar, ROT47, and Vigenere

Try the common self-inverse rotations:

```bash
zest -f text.txt rot
zest -f text.txt rot47
```

For Caesar, test shifts explicitly and stop when the flag format or language
context matches:

```bash
for n in $(seq 1 25); do
  printf 'shift=%s\n' "$n"
  zest -f text.txt rot:amount="$n" | grep -E "$FLAG_RE|[A-Za-z]{4,}" || true
done
```

For a known Vigenere key:

```bash
zest -f cipher.txt vigenere-decode:key='LEMON' -o "$case_dir/vigenere.txt"
grep -E "$FLAG_RE" "$case_dir/vigenere.txt"
```

Zest does not recover unknown Vigenere keys.

## Known-parameter AES

Use this only when the challenge provides enough parameters: mode, key, IV/nonce,
ciphertext format, and any GCM AAD/tag convention. Use env or files for secrets;
challenge-published constants may be literals.

```bash
export AES_KEY='hex:00112233445566778899aabbccddeeff'
export AES_IV='hex:0102030405060708090a0b0c'
zest -f ciphertext.hex aes-decrypt:key=env:AES_KEY,iv=env:AES_IV,mode=GCM,input=Hex -o "$case_dir/plain.bin"
```

For CBC or CTR:

```bash
zest -f ciphertext.b64 aes-decrypt:key=env:AES_KEY,iv=env:AES_IV,mode=CBC,input=Base64 -o "$case_dir/plain.bin"
zest -f ciphertext.bin "aes-decrypt:key=file:$case_dir/aes.key,iv=file:$case_dir/aes.iv,mode=CTR,input=Raw bytes" -o "$case_dir/plain.bin"
```

Check output type and flag:

```bash
zest -f "$case_dir/plain.bin" detect-file-type
zest -f "$case_dir/plain.bin" strings:minLength=4 | grep -E "$FLAG_RE"
```

If parameters are missing, Zest will not crack or derive them except for explicit
`derive-aes-key` inputs supplied by the challenge. Hand off for cryptanalysis.

## Hashes and checksums

Identify shape, but do not treat shape as proof:

```bash
zest -i "$DIGEST" analyse-hash
```

When a candidate plaintext or file is available, compute and compare:

```bash
zest -f candidate.bin md5
zest -f candidate.bin sha1
zest -f candidate.bin sha2:size=SHA-256
zest -f candidate.bin sha3:size=256
zest -f candidate.bin keccak:size=256
zest -f candidate.bin crc32
zest -f candidate.bin adler32
```

For HMAC with a provided key:

```bash
zest -f message.bin hmac:key=env:HMAC_KEY,algorithm=SHA-256
```

Zest does not crack hashes. If the challenge asks for password recovery, hand off
to approved cracking tooling and rules for the event.

## JWT, URL, HTML, and web tokens

Decode web wrappers in the smallest useful step:

```bash
zest -f token.txt jwt-decode
zest -f url.txt parse-uri
zest -f query.txt parse-query-string:format=JSON
zest -f encoded.txt url-decode:plusIsSpace=true
zest -f html.txt from-html-entity
```

For nested web encoding:

```bash
zest -f value.txt url-decode:plusIsSpace=true from-base64 json-format
```

JWT decoding is not verification. For HS256/384/512 with a provided secret:

```bash
zest --input-env JWT jwt-verify:secret=env:JWT_SECRET
```

If the token uses asymmetric JWT algorithms, Zest can decode but not verify them.
Hand off to JWT tooling with the public key.

## Artifact triage and offset carving

Preserve the original and inspect signatures, strings, entropy, and offsets:

```bash
zest -f sample.bin detect-file-type
zest -f sample.bin hexdump -o "$case_dir/sample.hex"
zest -f sample.bin entropy:blockSize=512
zest -f sample.bin strings:minLength=6,showOffsets=true -o "$case_dir/strings.txt"
```

When evidence shows a payload starts at an offset, carve with `take-bytes`:

```bash
zest -f sample.bin take-bytes:start=128 -o "$case_dir/carve-0x80.bin"
zest -f "$case_dir/carve-0x80.bin" detect-file-type
```

When evidence shows a wrapper/header length:

```bash
zest -f sample.bin drop-bytes:start=0,length=128 -o "$case_dir/without-header.bin"
```

When evidence shows an embedded run length:

```bash
zest -f sample.bin take-bytes:start=4096,length=2048 -o "$case_dir/payload-0x1000.bin"
```

Use `hexdump:offset=N` only to display offsets correctly after slicing:

```bash
zest -f "$case_dir/payload-0x1000.bin" hexdump:offset=4096 | head -40
```

Zest can carve by known offsets but does not scan and extract every embedded file
automatically.

## ZIP, image, PCAP, and binary handoffs

Use Zest to decide the boundary, then hand off instead of hallucinating commands.

```bash
zest -f artifact.bin detect-file-type
zest -f artifact.bin strings:minLength=6,showOffsets=true
zest -f artifact.bin hexdump | head -80
```

Hand off when the next required operation is outside Zest:

- ZIP or nested archives: use archive tooling; Zest does not list or extract ZIPs.
- Images with EXIF, LSB, palette, appended-data, or stego claims: use image/stego tooling. Zest can inspect bytes and carve known offsets only.
- PCAPs: use packet tools; Zest does not parse protocols or streams.
- Native binaries: use strings, headers, and byte views for triage only. For disassembly, decompilation, emulation, or dynamic analysis, hand off to reversing tools.
- RSA, ECC, lattice, modular arithmetic, password cracking, or unknown-key recovery: hand off to crypto/math/cracking tools.

Recommended handoff note:

```text
Zest evidence: <operation output summary>. Boundary: <unsupported next step>.
Recommended tool/specialist: <archive|pcap|stego|reversing|crypto math|cracking>.
```
