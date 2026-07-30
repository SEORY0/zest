---
name: zest-triage
description: Triage an unknown or suspicious artefact — a file, a captured blob, a log, a phishing mail, an obfuscated string — using the local `zest` CLI. Identifies file type from magic bytes, measures entropy to spot encryption or packing, extracts strings and indicators, defangs and refangs IOCs, and works out what an encoded payload actually is. Use when asked "what is this file", "is this packed", "what is in this sample" or "pull the indicators out of this".
---

# Triage with Zest

A repeatable first pass over an artefact you have not seen before. Everything runs locally, so
the sample never leaves the machine.

## Setup

This skill drives the `zest` command. Check for it with `zest --version`; if it is missing:

```bash
git clone https://github.com/SEORY0/zest.git
cd zest && npm install && npm run build && npm link -w @zest/cli
```

See the companion `zest` skill for the general command model; this one is the investigative
procedure built on top of it.

## Ground rules

- **Never execute the sample.** Every step here reads bytes; nothing runs them.
- **Never upload it.** `zest` has no network capability, and neither should the rest of your
  workflow unless the person asked for it explicitly.
- **Report what you observed, separately from what you infer.** "Entropy is 7.94" is an
  observation. "Probably packed" is an inference. Keep them apart.
- **Defang indicators before putting them in a report** so nobody clicks them by accident.

## The pass

### 1. What is it?

```bash
zest -f sample.bin detect-file-type
```

Reports every matching signature with its offset. Overlaps are meaningful: a ZIP header also
covers `.docx`, `.jar`, `.apk` and `.epub`, so a ZIP match on a file called `invoice.doc` is
worth noting.

If nothing matches, look at the head directly:

```bash
zest -f sample.bin take-bytes:start=0,length=64 hexdump
```

### 2. Is it encrypted, compressed or packed?

```bash
zest -f sample.bin entropy:blockSize=4096
```

Read the whole-file figure first, then the per-block chart:

| Entropy (bits/byte) | Reading |
| --- | --- |
| < 1 | padding or a repeated fill byte |
| 3–5 | natural language, source code, plain structured text |
| 6–7 | encoded, or dense binary such as an executable |
| > 7.5 | encrypted, compressed, or otherwise random |

A file that is mostly ~6 with one sustained > 7.5 region is the classic shape of a packed
binary or an embedded encrypted payload. Use the block offsets to carve it:

```bash
zest -f sample.bin take-bytes:start=8192,length=4096 -o payload.bin
```

### 3. What does it say?

```bash
zest -f sample.bin strings:minLength=6,showOffsets=true
```

Add `encoding=UTF-16LE` when triaging Windows binaries — a great deal of interesting text there
is wide, and an ASCII-only pass misses it.

### 4. What does it reach out to?

```bash
zest -f sample.bin strings:minLength=6 | zest extract-indicators
```

Groups URLs, domains, IPv4, IPv6, email addresses and hashes. Domains that already appear inside
a URL or email are not repeated. To narrow:

```bash
zest -f mail.eml extract-indicators:kind=URL
```

### 5. What is the encoded part?

When strings turns up something that is clearly encoded but not obviously what:

```bash
zest -i "$BLOB" magic:depth=3
```

If you know a word that must appear in the plaintext, say so — it cuts through everything:

```bash
zest -i "$BLOB" magic:depth=3,crib=http,intensive=true
```

`intensive=true` adds all 256 single-byte XOR keys, which is the most common obfuscation in
loaders and droppers. For a XOR key specifically:

```bash
zest -i "$HEX" xor-brute-force:crib=http
```

### 6. Record the identity

```bash
zest -f sample.bin sha2:size=SHA-256
zest -f sample.bin md5
```

Report SHA-256 as the identifier. MD5 is worth including only because external references still
key on it — say so rather than presenting it as an integrity guarantee.

## Reporting

Defang everything before it lands in a document or a chat message:

```bash
zest -i 'https://evil.test/payload' defang
# hxxps://evil[.]test/payload
```

To act on an indicator someone sent you defanged:

```bash
zest -i 'hxxps://evil[.]test/a' fang
```

A useful shape for the write-up:

```
Artefact    invoice_2024.doc
SHA-256     <digest>
Type        ZIP archive (signature says ZIP, extension says DOC)
Entropy     6.1 overall; 7.9 across bytes 0x2000–0x3000
Strings     hxxps://evil[.]test/a, "powershell -enc"
Assessment  Office document with an embedded high-entropy region and a
            defanged outbound URL. Consistent with a macro dropper.
Confidence  Medium — based on static indicators only; not detonated.
```

## Other artefacts

**A JWT from a bug report**

```bash
zest -i "$TOKEN" jwt-decode
```

Check `alg` first. `alg: none` is flagged explicitly and means a verifier honouring it accepts
anything. Then read the `claims as dates` block for expiry.

**A password hash**

```bash
zest -i "$HASH" analyse-hash
```

Identifies crypt(3)-style prefixes exactly, and otherwise gives a shortlist by digest length.
A shortlist is the honest answer — many algorithms share a size.

**A Windows timestamp from the registry or an event log**

```bash
zest -i 133445222400000000 filetime-to-date
```

**A capture that is base64 inside JSON**

```bash
zest -f capture.json json-path:path=data.payload from-base64 gunzip json-format
```

## Reference

- `references/operations.md` — every operation, its arguments and worked examples
