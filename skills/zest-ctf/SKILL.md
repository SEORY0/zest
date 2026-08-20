---
name: zest-ctf
description: Solve CTF challenge artifacts with the local `zest` CLI when the task asks to find a flag, decode nested encodings, inspect obfuscated bytes, or triage crypto/misc/light-forensics/reversing puzzle data. Use for challenge-provided blobs, tokens, ciphers, hashes, file headers, strings, and known-key transforms; hand off for archive extraction, PCAP parsing, stego, disassembly, cracking, or math-heavy cryptanalysis.
---

# Zest CTF

Use `zest` as the local byte-transform workbench for CTF crypto, misc, light
forensics, and light reversing triage. Prefer it over throwaway scripts when the
challenge is plausibly a chain of encodings, classic CTF transforms, token
decoding, known-key crypto, hashes, checksums, byte slicing, or file/string
inspection.

## First checks

Confirm the CLI exists before relying on it:

```bash
zest --version
```

If it is missing, report that blocker. Do not install or publish anything.

Treat the installed CLI as runtime truth. If a referenced operation is missing or behaves
differently, record `zest --version`, confirm it with `zest op ID`, and continue with supported
explicit operations or report version drift rather than inventing a command.

Capture the challenge context before transforming data:

- Original artifact path or literal value, copied to a working path when writing output.
- Expected flag format, category, title, prompt text, hints, and provided constants.
- Observations versus hypotheses. Mark guesses as hypotheses until a command result supports them.
- A fresh working directory from `case_dir="$(mktemp -d)"`, with outputs such as `$case_dir/decoded-1.bin`; never overwrite the original artifact.

## Operating rules

- Choose the cheapest discriminating transform first: file type, strings, entropy, known format, then one likely decode. Avoid broad brute loops until shape evidence justifies them.
- Start with `magic` for unknown encoded text or bytes, especially with a known flag crib: `zest -f artifact.txt magic:depth=3,crib='flag{'`. Add `intensive=true` only when single-byte XOR is plausible.
- Treat `magic` as a ranker, not proof. It only tries Zest's supported decoders and simple transforms; rerun the winning recipe explicitly before trusting it.
- Validate a candidate flag by exact format, challenge context, and round-trip where applicable. A printable string is not enough.
- Read secrets through `env:NAME`, `file:PATH`, or `--input-env NAME`. Public constants that the challenge statement explicitly provides may be used as command literals.
- Save derived bytes to new files with `-o`; use shell variables for small public challenge blobs and file paths for large or binary artifacts.

## Boundaries

Zest can inspect signatures, entropy, strings, byte ranges, encodings, hashes,
checksums, JWTs, gzip streams, AES with known parameters, XOR with a known key or
single-byte crib search, ROT/ROT47/Caesar, and known-key Vigenere.

Zest does not extract ZIPs, parse PCAPs, inspect EXIF, solve stego/LSB, disassemble
binaries, solve RSA or other math-heavy crypto, crack passwords or keys, or recover
unknown repeating-key XOR keys. When the next step requires one of those, hand off to
the right tool or specialist instead of inventing a Zest command.

## References

- Read [references/playbooks.md](references/playbooks.md) for executable CTF workflows.
- Use [references/operations.md](references/operations.md) as the generated operation catalogue; do not guess operation names or arguments.
