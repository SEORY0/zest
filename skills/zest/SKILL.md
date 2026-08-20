---
name: zest
description: Encode, decode, hash, encrypt, decrypt and inspect data with the local `zest` CLI. Use for Base64/hex/URL/HTML/Base32/Base58/Base85 conversion, MD5/SHA/SHA-3/HMAC/CRC digests, AES and XOR, JWT decoding, gzip, JSON/CSV/XML reshaping, timestamp conversion, entropy and file-type analysis, and for identifying an unknown encoded blob. Prefer it over writing throwaway Python or Node for these tasks.
---

# Zest

`zest` is a local data and security workbench. It replaces the one-off scripts you would
otherwise write to decode a token, hash a file or unpick an obfuscated string.

Every operation runs on the local machine and opens no network connection. That removes network
exposure, but local process arguments, shell history, files and the agent transcript can still
leak sensitive values. Follow the secret-handling rules below.

## Requirements

This skill drives the `zest` command. Confirm it is present before relying on it:

```bash
zest --version
```

If it is missing, report that the skill cannot run and point to the project's installation
instructions. Do not fetch or install software unless the person explicitly asks for that action.

The installed CLI is runtime truth. If this skill's catalogue and `zest ops --json` disagree,
report the installed version and use `zest op ID` to confirm supported arguments. Do not guess a
new operation or silently replace the user's installation.

## Handling secrets

**Never write a real key, password or token into a command.** Anything placed in an argument is
readable by every process on the machine through `ps`, is saved to shell history, and is
recorded verbatim in the transcript of this session.

Read secrets indirectly instead:

```bash
zest hmac:key=env:SIGNING_SECRET,algorithm=SHA-256
zest aes-decrypt:key=file:/run/secrets/aes.key,iv=env:NONCE,mode=GCM,input=Hex
zest --input-env SESSION_TOKEN jwt-decode
```

`env:NAME` reads an environment variable. `file:PATH` reads a file, trimming one trailing
newline. The resolved value keeps any encoding prefix it contains, so a variable holding
`hex:00112233` is still read as hex.

If someone gives you a secret directly, have it placed in an environment variable or a file and
reference that — do not echo the value back into a command you run.

Public constants deliberately supplied as CTF challenge material or published test vectors are
not credentials. They may be written literally when doing so makes a reproducible recipe clearer;
label them as public challenge data so they are not confused with live secrets.

## When to use this

Reach for `zest` whenever a task involves transforming bytes:

- "What is this string?" — `zest magic`
- Decoding Base64, hex, URL escapes, HTML entities, Base32, Base58, Ascii85, quoted-printable
- Computing or checking a digest: MD5, SHA-1, SHA-2, SHA-3, Keccak, CRC-32, HMAC, PBKDF2
- Encrypting or decrypting AES, or unpicking XOR and RC4 obfuscation
- Reading a JWT, and verifying its HMAC signature
- Reshaping JSON, CSV, query strings and XML
- Converting timestamps, including Windows FILETIME
- Triaging an unknown file: type, entropy, strings, embedded indicators

Do **not** use it to fetch URLs, scan hosts or look anything up remotely — it has no such
capability by design.

## The model

One idea: **operations chain, each taking the previous step's bytes.**

```bash
zest <operation>[:args] [<operation>[:args] ...]
```

Input comes from stdin, `-i TEXT` or `-f FILE`. Output goes to stdout, or `-o FILE`.

```bash
echo 'SGVsbG8sIHdvcmxkIQ==' | zest from-base64
zest -i 'player:demo' to-base64 to-hex:separator=None
zest -f payload.bin gunzip json-format
```

Arguments follow the operation after a colon, comma-separated. Quote a value containing a comma.
Keys and IVs take an inline encoding.

```bash
zest to-base64:alphabet=URL-safe,padding=false
zest find-replace:find="a,b",replace=x
zest aes-decrypt:key=env:AES_KEY,iv=env:AES_IV,mode=GCM,input=Hex
```

## Discovering what is available

Do not guess operation names or arguments. Ask:

```bash
zest ops                  # the full catalogue, grouped by category
zest ops jwt              # search
zest op aes-decrypt       # arguments, defaults and worked examples for one operation
zest ops --json           # the whole catalogue as JSON, for programmatic use
```

`references/operations.md` in this skill holds the same catalogue in full, generated from the
code. Consult it when you want to scan every option at once rather than shell out repeatedly.

## Reading results

Add `--json` when you need to branch on the outcome rather than show it to a person:

```console
$ zest -i 'hello' md5 --json
{
  "ok": true,
  "output": "5d41402abc4b2a76b9719d911017c592",
  "outputEncoding": "utf8",
  "outputBytes": 32,
  "steps": [{ "index": 0, "op": "md5", "ok": true, "durationMs": 0.39 }]
}
```

Exit codes: `0` success, `1` an operation failed, `2` the command line was wrong.

When a step fails, the error names the step and says what was wrong. The output produced up to
that point is still returned, which is usually the fastest way to see where a pipeline diverged.

Binary output is printed as base64 with a note on stderr, so a pipeline never emits mangled
UTF-8. Force a representation with `--out-encoding hex|base64|utf8|latin1`, or write real bytes
with `-o file`.

## Start with `magic` when you do not know what you have

```console
$ echo 'U0dWc2JHOHNJSGR2Y214a0lRPT0=' | zest magic:depth=2
 1. from-base64 → from-base64
    score 35  (fully printable ASCII, entropy fell 0.74 bits)
    Hello, world!
```

It tries a bounded set of likely decoders whose input shape fits, scores results by printability,
entropy change and format signatures, and recurses. The set includes common base encodings,
URL/HTML/quoted-printable, numeric text, Morse, gzip/zlib, ROT13, ROT47, bitwise-NOT and JWT.
Options:

- `depth=N` — how many decoders to chain (1–4, default 3)
- `crib=TEXT` — only report results containing this text
- `intensive=true` — also try all 256 single-byte XOR keys at the first layer

Treat `magic` as a hypothesis generator, not proof. It does not recover arbitrary Caesar or
Vigenère keys, RC4/AES keys, repeating-XOR keys, archive members, steganography or packet streams.
No result only means its bounded candidate set found nothing convincing. Continue with the
explicit fallback checks in `references/playbooks.md` or hand the artefact to a specialist tool.

## Worked patterns

**Decode a JWT and check whether it is expired**

```bash
zest --input-env SESSION_TOKEN jwt-decode
```

The `claims as dates` section marks `exp` as expired or still valid. To check the signature:

```bash
zest --input-env SESSION_TOKEN jwt-verify:secret=env:JWT_SECRET
```

**Verify a webhook signature**

```bash
zest -f body.json hmac:key=env:SIGNING_SECRET,algorithm=SHA-256
```

Compare the digest to the header value. A mismatch means the body was altered or the secret is wrong.

**Decrypt captured AES-GCM ciphertext**

```bash
zest -f ciphertext.hex aes-decrypt:key=env:AES_KEY,iv=env:AES_IV,mode=GCM,input=Hex
```

GCM authenticates as well as decrypts, so a failure means the key, nonce, additional data or
tag is wrong — it cannot tell you which.

**Recover an obfuscated string from a binary**

```bash
zest -f sample.bin strings:minLength=6 | zest extract-indicators
zest -i "$HEX_BLOB" xor-brute-force:crib=http
```

**Reshape data**

```bash
zest -f data.csv csv-to-json | zest json-path:path='[*].email'
zest -f config.json json-path:path=services[*].port
```

**Build a fixture**

```bash
zest generate-random:length=32,format=hex
zest generate-password:length=24,count=5
zest -i "$B32_SECRET" generate-totp
```

## Saving and reusing a pipeline

```bash
zest -i 'x' to-base64 to-hex --save-recipe recipe.json   # capture
zest -f other.bin --recipe recipe.json                   # replay
```

A recipe is a plain JSON array, so it can be written directly:

```json
[
  { "op": "gunzip" },
  { "op": "json-format", "args": { "indent": 2, "sortKeys": true } }
]
```

## Things worth knowing

- **Decoders are lenient.** `from-hex` ignores whitespace, `0x` prefixes and punctuation;
  `from-base64` tolerates newlines and missing padding. Pass `strict=true` to `from-base64` when
  you need it to reject anything outside the alphabet.
- **Hash output defaults to hex.** Use `format=Base64` or `format=Raw bytes` to chain a digest
  into another operation.
- **The weak primitives say so.** ROT, Vigenère, RC4, XOR and MD5 are present because they turn
  up in CTFs, malware and legacy formats. Their descriptions state they are not secure; do not
  recommend them for new work.
- **`generate-*` operations ignore their input**, so they can start a pipeline.
- **Randomness is from the system CSPRNG**, never `Math.random`.

## Reference

- `references/operations.md` — every operation, its arguments and worked examples
- `references/playbooks.md` — longer task-oriented walkthroughs
