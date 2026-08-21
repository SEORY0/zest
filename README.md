# Zest

A local-first data and security workbench — a browser app, a CLI, and four agent skills over
one engine.

Chain operations into a recipe the way you would in CyberChef, but with a calmer interface, a
CLI that composes with the rest of your shell, and skills so an agent can use the same 103
operations instead of writing throwaway scripts.

Nothing opens a network connection. The browser app has no backend; the CLI makes no requests.
Inputs stay on the device, though real secrets still need env/file discipline so they do not
leak through process arguments, shell history or agent transcripts.

**[Try it →](https://seory0.github.io/zest/)**

## Layout

| Package | What it is |
| --- | --- |
| `packages/core` | The engine. Zero dependencies, isomorphic, 103 operations, 219 tests. |
| `packages/cli` | The `zest` command. |
| `packages/web` | The browser workbench. |
| `skills/zest` | Agent skill for the general workbench. |
| `skills/zest-ctf` | Agent skill for CTF byte and encoding puzzles, plus first-pass artefact solving. |
| `skills/zest-crypto` | Agent skill for math-heavy and paper-derived CTF cryptography. |
| `skills/zest-triage` | Agent skill for triaging an unknown artefact. |

## Getting started

```bash
npm install
npm run build      # core + cli
npm test           # engine tests + standalone skill package checks
npm run dev        # the workbench at http://localhost:5173
```

To use the CLI from anywhere:

```bash
npm link -w @zest/cli
```

## The CLI

Operations chain left to right, each taking the previous step's bytes.

```console
$ echo 'SGVsbG8sIHdvcmxkIQ==' | zest from-base64
Hello, world!

$ zest -i 'player:demo' to-base64 to-hex:separator=None
63477868655756794f6d526c6257383d

$ zest -f capture.bin gunzip json-format
```

Arguments follow a colon. Keys and IVs carry their encoding inline.

```console
$ zest to-base64:alphabet=URL-safe,padding=false
$ zest aes-decrypt:key=hex:0011...,iv=hex:aabb...,mode=GCM,input=Hex
```

Discover what exists rather than guessing:

```console
$ zest ops              # the catalogue, grouped
$ zest ops jwt          # search
$ zest op aes-decrypt   # arguments, defaults, worked examples
$ zest ops --json       # the catalogue as JSON
```

Add `--json` for a structured result with per-step timings. Exit codes are `0` success,
`1` operation failure, `2` usage error.

### Magic

When you do not know what you are holding:

```console
$ echo 'U0dWc2JHOHNJSGR2Y214a0lRPT0=' | zest magic:depth=2
 1. from-base64 → from-base64
    score 35  (fully printable ASCII, entropy fell 0.74 bits)
    Hello, world!
```

It ranks a bounded set of decoders and simple transforms whose input shape fits, scores what
comes back by printability, entropy change and format signatures, and recurses. `crib=TEXT`
narrows to results containing known plaintext; `intensive=true` adds all 256 single-byte XOR
keys. No result is not proof that the input is plaintext or encrypted.

## The workbench

```bash
npm run dev
```

Three panes: the operation library, the recipe, and input/output. Steps reorder by drag or with
the arrow buttons, and can be disabled without being removed — useful for bisecting a pipeline
that stopped working. The recipe is held in the URL fragment, so a link reproduces it; the input
is deliberately excluded, since that is usually the sensitive half.

Output carries a byte count, live Shannon entropy and a file-type guess, so you can tell whether
a decode worked without reading it.

## Agent skills

```bash
npx skills add SEORY0/zest-skill
```

That installs all four skills into whichever agents it finds — Claude Code, Codex, Gemini CLI
and the rest. To install only the mathematical cryptanalysis workflow:

```bash
npx skills add SEORY0/zest-skill --skill zest-crypto
```

Use `--skill zest`, `--skill zest-ctf` or `--skill zest-triage` to take one of the other workflows.
They are listed on
[skills.sh](https://www.skills.sh/SEORY0/zest-skill).

The skills live in `skills/` here and are mirrored to
[SEORY0/zest-skill](https://github.com/SEORY0/zest-skill) so installing one does not pull the
whole workbench. This repository is the source of truth; run `npm run publish:skill` after
changing anything under `skills/`.

The skills drive the `zest` CLI, so install that too (`npm link -w @zest/cli` above).

`skills/zest` teaches the command model, discovery and result handling. `skills/zest-ctf`
organises flag-focused byte and encoding puzzles: transforms, XOR/classical ciphers, known-key
crypto, hashes, web tokens and byte carving. `skills/zest-crypto` handles math-heavy,
paper-derived work involving RSA, ECC, lattices, signatures, PRNGs and crypto oracles; it solves
supported families, researches exact sources only when authorized, and reports blocked or
unsupported cases rather than claiming every construction is solvable. `skills/zest-triage` is a
procedure for unknown artefacts: identify by magic bytes, measure entropy, extract strings and
indicators, defang for reporting.

`references/operations.md` in each skill is generated from the registry by `npm run docs`, so the
catalogue an agent reads always matches the code.

## What is in it

**Encoding** — Base64 (standard, URL-safe, custom alphabets), Base32, Base58, Ascii85, hex,
URL, HTML entities, quoted-printable, character codes in any base, Morse, Latin-1 repair.

**Hashing** — MD5, SHA-1, SHA-2, SHA-3, Keccak, HMAC, CRC-32, Adler-32, PBKDF2.

**Encryption** — AES in GCM, CBC and CTR; XOR and single-byte XOR brute force; RC4; ROT and
ROT47; Vigenère; bit rotation; PBKDF2 key derivation.

**Text** — case conversion, sort, unique, filter, find and replace, regex extract, split and
join, padding, escaping.

**Data** — JSON format, minify and path extraction; CSV and JSON conversion; JWT decode and
HMAC verification; query strings; XML formatting.

**Compression** — gzip, zlib and raw deflate, with format detection on decompress.

**Network** — defang and refang, IPv4 and integer conversion, CIDR expansion, URI parsing,
indicator extraction.

**Analysis** — hex dump and its inverse, Shannon entropy with per-block charting, byte
frequency, file type from magic bytes, string extraction, hash identification, byte slicing,
and Magic.

**Date & time** — Unix timestamps in four units, Windows FILETIME, interval shifting.

**Generate** — UUIDs, random bytes, passwords with a stated entropy figure, TOTP codes.

## Correctness

Crypto goes through WebCrypto rather than a hand-rolled implementation, because reimplementing a
block cipher is exactly the thing this tool should not do. What WebCrypto does not offer — MD5,
CRC-32, Adler-32, Keccak, RC4, Base32/58/85 — is implemented here and checked against its
defining document: RFC 1321, FIPS 202, RFC 4231, RFC 2202, RFC 6070, RFC 6238, RFC 4648, and
NIST SP 800-38A.

Every operation also carries worked examples, and those examples *are* the test suite — the
docs cannot drift from the behaviour.

```console
$ npm test
# core: 219 passed
# skill package: 2 passed
```

## Design

The interface follows the design system at [oklch.fyi](https://oklch.fyi): a twelve-step grey
ramp, surfaces raised by a hairline ring and a soft shadow rather than a border, a 0.375–1rem
radius scale, and sans for chrome against mono for data. Light and dark are both first-class.

## Licence

MIT.
