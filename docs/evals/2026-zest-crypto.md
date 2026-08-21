# Zest Crypto 2026 Evaluation

Date: 2026-08-21

This report records the Task 8 evaluation of the standalone `zest-crypto` skill on pinned 2026 CTF cryptography benchmarks. It does not claim universal cryptanalysis capability: the skill supports the cataloged families below, uses research fallback only when authorized, and reports `blocked` or `unsupported` when evidence or tooling is insufficient.

No full flag strings, live challenge endpoints, official solver code, or third-party challenge artifacts are copied here.

## Provenance

| Event | Metadata | Immutable source |
| --- | --- | --- |
| UofTCTF 2026 MAT347 | Crypto, 500-point dynamic challenge, 8/1736 solves verified from the pinned [`README.md`](https://github.com/UofTCTF/uoftctf-2026-chals-public/blob/8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/README.md) | [`UofTCTF/uoftctf-2026-chals-public@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/mat347/dist/chall.py`](https://github.com/UofTCTF/uoftctf-2026-chals-public/blob/8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/mat347/dist/chall.py) |
| UofTCTF 2026 Rotor Cipher | Crypto, 500-point dynamic challenge, 74/1736 solves verified from the pinned [`README.md`](https://github.com/UofTCTF/uoftctf-2026-chals-public/blob/8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/README.md) | [`UofTCTF/uoftctf-2026-chals-public@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/rotor-cipher/rotor_cipher.py`](https://github.com/UofTCTF/uoftctf-2026-chals-public/blob/8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/rotor-cipher/rotor_cipher.py) |
| BSidesSF 2026 lfstream | Crypto, `metadata.yml` value 1000 | [`BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330/lfstream/challenge/lfsr_crypt.py`](https://github.com/BSidesSF/ctf-2026-release/blob/68ee0e460eb572aaec17f082071f8ebf1d6f7330/lfstream/challenge/lfsr_crypt.py) |
| BSidesSF 2026 tokencrypt | Crypto/Terminal, `metadata.yml` value 1000 | [`tc_demo.py`](https://github.com/BSidesSF/ctf-2026-release/blob/68ee0e460eb572aaec17f082071f8ebf1d6f7330/tokencrypt/challenge/src/tc_demo.py), [`tokencrypt.py`](https://github.com/BSidesSF/ctf-2026-release/blob/68ee0e460eb572aaec17f082071f8ebf1d6f7330/tokencrypt/challenge/src/tokencrypt.py) |
| BSidesSF 2026 kproof | Crypto, `metadata.yml` value 1000 | [`BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330/kproof/challenge/src/kproof.go`](https://github.com/BSidesSF/ctf-2026-release/blob/68ee0e460eb572aaec17f082071f8ebf1d6f7330/kproof/challenge/src/kproof.go) |
| SekaiCTF 2026 apbq-rsa-iv | Crypto, 327 points, 11 solves, `5`-star Master difficulty | [`project-sekai-ctf/sekaictf-2026@e35651f972e1c4f355c18427b3063a9ac98fb2cd/crypto/apbq-rsa-iv/challenge/apbq-rsa-iv.py`](https://github.com/project-sekai-ctf/sekaictf-2026/blob/e35651f972e1c4f355c18427b3063a9ac98fb2cd/crypto/apbq-rsa-iv/challenge/apbq-rsa-iv.py) |

Pinned source spans used by the catalog:

- MAT347: `mat347/dist/chall.py:L24-L55`
- Rotor Cipher: `rotor-cipher/rotor_cipher.py:L46-L149`
- lfstream: `lfstream/challenge/lfsr_crypt.py:L4-L45`
- tokencrypt: `tokencrypt/challenge/src/tc_demo.py:L12-L175` and `tokencrypt/challenge/src/tokencrypt.py:L11-L326`
- kproof: `kproof/challenge/src/kproof.go:L64-L690`
- Sekai separate non-blind confirmation: [`solution/solve.sage:L1-L55`](https://github.com/project-sekai-ctf/sekaictf-2026/blob/e35651f972e1c4f355c18427b3063a9ac98fb2cd/crypto/apbq-rsa-iv/solution/solve.sage)

## Routing Fixtures

Local deterministic checks validated the 21-card catalog and routed the five 2026 fixtures against `skills/zest-crypto/references/attack-cards.json`.

Commands:

```bash
python3 skills/zest-crypto/scripts/validate_attack_cards.py skills/zest-crypto/references/attack-cards.json
node --test --test-name-pattern='2026|routing|lfstream|rotor|tokencrypt|kproof|mat347' scripts/zest-crypto-tools.test.mjs
for f in scripts/fixtures/zest-crypto/fingerprints/2026/*.json; do
  python3 skills/zest-crypto/scripts/rank_attack_cards.py "$f" skills/zest-crypto/references/attack-cards.json
done
```

Observed validation:

- Catalog: `{"card_count":21,"issues":[],"ok":true}`
- Routing tests: 2 passed, 0 failed
- Catalog digest reported by ranker: `1867e0a3df1e4d9d824cb1f672404061fbe8c96e0e8304288b0381d5e2427cd4`

| Fixture | Intended card | Deterministic state | Top-three order checked |
| --- | --- | --- | --- |
| MAT347 | `lattice.subset-sum.query-schedule` | top-one `eligible` | `lattice.subset-sum.query-schedule` |
| Rotor Cipher | `symmetric.rotor.group-conjugacy` | top-one `eligible` | `symmetric.rotor.group-conjugacy` |
| lfstream | `stream.lfsr.known-plaintext` | top-one `eligible` | `stream.lfsr.known-plaintext` |
| tokencrypt | `symmetric.slide.periodic-round` | top-one `eligible` | `symmetric.slide.periodic-round` |
| kproof | `oracle.goldwasser-micali.replication` | top blocked, rule `authorized-gm-wrapper-oracle` | `oracle.goldwasser-micali.replication`, `prng.mt19937.state-clone`, `rsa.hastad.broadcast` |

The `kproof` fixture is intentionally not eligible: its live-query authorization/budget fact remains inferred, so hard preconditions block the GM replication card.

## Blind Evaluation

The following results come from independent blind agent runs over sanitized local case directories and the skill package. Static challenge metadata, official solution directories, actual flags, live endpoints, and prior reports were not provided as inputs. The Rotor run derived a candidate during solving; this committed report retains only its digest, not the value.

The Sekai official-solution research note was created earlier in a separate non-blind lane. The blind agent ran with a fresh context, an explicit allowlist limited to its sanitized inputs and the skill, and no network access. That procedural isolation is recorded honestly; filesystem timestamps alone cannot prove non-access to every pre-existing local artifact.

| Case | First justified hypothesis | Elapsed / total timing | Result |
| --- | --- | --- | --- |
| MAT347 | `lattice.subset-sum.query-schedule` after `82.731952148 s` | total `344.135124987 s` | Honest `blocked`: Sage was unavailable, source-only input had no oracle, transcript, public-key session, ciphertext, or live instance; an 8-bit source-faithful counter-wrap toy verified the algebraic invariant. |
| lfstream | `stream.lfsr.known-plaintext`; source-identification phase had no separate timestamp | total `168.050 s`; bounded recovery plus replay `2.9 s` | End-to-end proof completed using known PNG header and LFSR schedule. |
| tokencrypt | `symmetric.slide.periodic-round` after `60.763110929 s` | total `627.532844027 s`; exhaustive local core scan about 40 s after a rejected input schedule | Honest `blocked`: local toy recovered the effective Feistel core and affine map, but the blind case lacked same-session 16-round chosen pairs and encrypted 1024-round target tokens. |
| kproof | `oracle.goldwasser-micali.replication`; exact whole-run delta missing | bounded active command time under 10 s | Honest `blocked`: PCAP/source authenticated the wrapper shape, but there was no authorized live oracle or 128 replicated-vector responses. |
| Rotor Cipher | `symmetric.rotor.group-conjugacy` at `2026-08-21T23:02:02.398911551+09:00` | final solver started `23:16:58.124577379+09:00`, source replay started `23:17:05.165445463+09:00` | End-to-end proof completed against the distributed implementation and log. |
| Sekai apbq-rsa-iv | fixed-card miss, then unknown-divisor simultaneous rational reconstruction fallback at `2026-08-21T23:08:35+09:00` | sanitized inputs hashed `23:06:00+09:00`; report assembled `23:14:33+09:00` | Blind run blocked: no fixed AttackCard survived; research fallback lacked a theorem-backed lattice construction and SageMath. |

### lfstream Proof

Material blind commands:

```bash
python3 <skill>/scripts/fingerprint.py lfstream-2026 lfsr_crypt.py
python3 <skill>/scripts/validate_attack_cards.py <skill>/references/attack-cards.json
python3 <skill>/scripts/rank_attack_cards.py case/fingerprint.json <skill>/references/attack-cards.json
python3 case/solvers/lfsr_known_plaintext_adapted.py case/inputs/flag.png.enc_lfsr case/inputs/png_header.bin case/proof/recovered.png 32 1 700000
python3 case/proof/replay_verify.py case/inputs/flag.png.enc_lfsr case/proof/recovered.png case/inputs/png_header.bin 0x074188A5 0x82800010
sha256sum case/proof/recovered.png case/inputs/flag.png.enc_lfsr
```

Input digests:

- `lfsr_crypt.py`: `5b197b98bec16e8d013d292ffe2c297f17267598af7341c8502e0f7778011a1e`
- `png_header.bin`: `30188ad79779aa1ccbd6d9c05106cbc6a42919a5b8c54e28d70eb7ca23388a6a`
- `flag.png.enc_lfsr`: `3e23594a9b4e277afb64263d2db6b708bf511995b71b3ddd15e35c48c876d97b`

Proof predicates:

- Known-header replay matched exactly.
- Source-schedule plaintext-to-ciphertext round trip matched exactly.
- Independent replay covered `689374` state transitions.
- Ciphertext digest remained `3e23594a9b4e277afb64263d2db6b708bf511995b71b3ddd15e35c48c876d97b`.
- Recovered plaintext digest was `86e472071179abc0d47def8295f6778ecb60943399612ccce35855f8b1dbe948`, matching the pinned challenge-side `lfsr_flag.png` digest.

Artifact digests:

- Adapted solver: `430f8cd283f6033e42149486aef8ae5c6d3cdb05b04627f98273a468e366ee3a`
- Independent verifier: `348371e50e1dfa73b4ebebece0656d8d02d7b067255d4035c11af5f05b84dce5`
- Replay JSON: `67feeeefd2ff281e857ed6026d34bfbbea3ffb84121829829b439b9babc830fb`

### Rotor Cipher Proof

Material blind commands:

```bash
python3 <skill>/scripts/fingerprint.py rotor-blind-20260821T230046 rotor_cipher.py rotor_cipher.log
python3 <skill>/scripts/validate_attack_cards.py <skill>/references/attack-cards.json
python3 <skill>/scripts/rank_attack_cards.py .zest-crypto-case.8RMjBr/fingerprint-manual.json <skill>/references/attack-cards.json
python3 .zest-crypto-case.8RMjBr/solvers/rotor_group_conjugacy.py .zest-crypto-case.8RMjBr/notes/toy-conjugacy.json
pytest -q .zest-crypto-case.8RMjBr/solvers/test_rotor_solver.py
timeout 120s python3 .zest-crypto-case.8RMjBr/solvers/run_rotor_solver.py rotor_cipher.log
timeout 120s python3 .zest-crypto-case.8RMjBr/proof/original_implementation_replay.py
```

Input digests:

- `rotor_cipher.py`: `9ad2c069ef711ccc57216ccaab8d4490af0a71a267cd7aadeb88dc54e2101216`
- `rotor_cipher.log`: `a998212dac3a63e179c587b1a9cb41879d687da56fdb2fea96f30a2e7f828a34`

Proof predicates:

- Three recovered rotors were bijections over all 26 uppercase symbols.
- Recovered reflector was canonical and involutive under the supplied implementation.
- All 60 reconstructed log-state permutations produced one common reflector.
- 1,000 plaintext messages encrypted to the logged ciphertexts with the supplied class: 6,000 symbol checks.
- 1,000 logged ciphertexts decrypted back to plaintext with reset state: 6,000 symbol checks.
- The supplied sample ciphertext matched exactly.
- The challenge `format_flag` function returned the recovered formatted value; the value is intentionally omitted here.
- In a separate metadata-verification lane, the recovered format value SHA-256 was checked as `be36f14046b990930413e9580d2746fb4226e4bcc8d16f10e90d2f94e68062e4`, matching the exact static `challenge.yml` content digest without printing that content.

Artifact digests:

- Manual fingerprint: `e87e6173f6f4e8c3a7e3abc5894d3d96bbebf726320c37788cf8cee5273304eb`
- Toy conjugacy proof: `4c57262a28982d55a9d643e8984ea0ea21ffd3503f90bb90029f8b095063c8fc`
- Solver script: `97bc1934e6c1986eb99f888b029c85db6fe4eb89502c2ad111c0d152d3cc254b`
- Solver core: `4240feb09fee6ff0ae5b2f7d6d2bd8c5c51c883ea36810bad91919d65323304b`
- Original implementation replay harness: `8097f6984acd2684029869e3160ec75e07eebf292acd23f5f4e0b6468a3f4e5e`
- Manifest: `e909073ad99bd984963a09b9b5e2100cef444fbc62e8f4d59db21352d70623d6`

## Blocked and Unsupported Cases

Blocked-case blind command surfaces included `sha256sum` input manifests, bounded source reads with `sed`/`nl`, `validate_attack_cards.py`, `fingerprint.py`, `rank_attack_cards.py`, and bounded local Python probes. MAT347 additionally attempted `timeout 3s python3 chall.py`, which failed because SageMath was unavailable. Sekai additionally ran the packaged Wiener probe, concrete-instance arithmetic checks, and a deterministic factor-known toy.

MAT347 was correctly routed to a lattice/query-schedule attack. The blind run verified a reduced counter-wrap invariant and rejected standard ECDSA and Wagner substitutions. Full recovery stayed blocked because the available case had source only, no live/captured instance, and no SageMath installation.

tokencrypt was correctly routed to the periodic-round slide family. The blind run recovered the effective core and affine wrapper on a source-faithful local probe, including the public counter-XOR normalization. Full recovery stayed blocked because the blind inputs lacked a same-session 16-round chosen-input transcript and the 1024-round encrypted target tokens.

kproof was correctly routed to the GM ciphertext-replication wrapper, but only as a blocked card. The PCAP contained one historical successful submission and a verified certificate, not the 128 authorized replicated-vector oracle responses needed to classify the captured key bits. CBC padding was rejected because the response is a certificate hash, not a padding-validity oracle.

Sekai `apbq-rsa-iv` is the open-world fallback benchmark. In the blind run, no fixed card survived: nominal Wiener routing failed its exponent-size assumption and packaged probe, while univariate Coppersmith did not fit the homogeneous multivariate system. The best fallback was an unknown-divisor simultaneous-rational-reconstruction or multivariate-small-roots route, but the blind case had no local theorem/citation for the exact construction and SageMath was unavailable. A separate non-blind research lane inspected the official repository solver and confirmed that the intended path uses lattice reduction over relations derived from the hint ratios, followed by a small integer search and factor recovery; that confirmation is not counted as blind evidence, and no solver code or flag text is copied here.

## Limits

- The evaluation proves exact routing for five pinned 2026 fixtures, not arbitrary cryptography.
- End-to-end proof was achieved only for lfstream and Rotor Cipher.
- MAT347, tokencrypt, and kproof are honest blocked states, not hidden solves.
- Sekai is evidence for research fallback behavior: the isolated blind agent reached the right family but stopped at missing theorem/tooling. Official confirmation came from a separate non-blind lane and is not counted as blind evidence; the isolation is procedural rather than timestamp-proven.
- Network-disabled blind runs did not contact challenge services or validate scoreboard acceptance.
