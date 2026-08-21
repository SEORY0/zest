# PRNGs, streams, and oracles

Apply the six [literature and adaptation gates](../literature.md). For remote services,
the [catalog](../attack-cards.json) never widens authorization: use only an endpoint and
query budget already recorded by the case.

## `prng.mt19937.state-clone`

- **Observable signals:** MT19937, at least 624 consecutive aligned full 32-bit outputs,
  and the exact API word/byte transformation.
- **Equations:** Invert the published tempering xor/shift/mask map for each word, install
  624 recovered state words, then apply the standard twist recurrence.
- **Hard assumptions:** Outputs are untruncated, consecutive, aligned, and from standard
  MT19937 rather than a seed wrapper, alternate MT variant, or mixed output API.
- **Cheapest falsifier:** Untemper and retemper one word, then use a 624-word clone to
  predict held-out outputs.
- **Expected cost:** Low; linear-time bit operations over one state window.
- **Solver adaptation:** Implement exact inverse xor shifts, retain word order and index,
  and bound prediction count. No generic PRNG library is required.
- **Failure interpretation:** A failed retemper indicates a wrong output transform;
  failed prediction suggests misalignment, skipped draws, or a different generator.
- **Proof:** Retemper all recovered words and predict an independent post-window sequence.
- **Primary citation:** Matsumoto and Nishimura, *Mersenne Twister: A 623-dimensionally
  equidistributed uniform pseudo-random number generator*, DOI
  `10.1145/272991.272995`, 1998.
- **Pinned challenge example:** No external mapping is asserted in v1. Pin the exact
  output API and a held-out word sequence before eligibility.

## `oracle.cbc-padding`

- **Observable signals:** Authorized chosen-ciphertext access, CBC processing, a stable
  padding-valid versus padding-invalid response, and a recorded query cap.
- **Equations:** Mutating predecessor block `C_(i-1)` controls
  `P_i=D_K(C_i) XOR C_(i-1)`; force suffix bytes to padding value `j` and enumerate the
  next intermediate byte.
- **Hard assumptions:** The response distinction is reproducible under one fixed key,
  ciphertext mutation is accepted, recovery scope is exactly one byte, and the effective
  budget `min(oracle.query_budget,max_oracle_queries)` is at least 258.
- **Cheapest falsifier:** Reserve one known-valid control and one ambiguity perturbation;
  reject noisy response classes or a budget below the worst-case 256-guess byte search.
- **Expected cost:** Oracle-bound; one byte, at most 256 guesses, and two controls.
- **Solver adaptation:** Write a one-byte case-local probe with deterministic guess order,
  one ambiguity probe, transcript logging, timeout, and a hard effective query counter.
- **Failure interpretation:** Instability blocks the oracle; it is not permission to add
  timing amplification or more traffic.
- **Proof:** Replay the bounded transcript and independently verify the one recovered
  plaintext byte. Do not claim block or full-plaintext recovery from this card.
- **Primary citation:** Vaudenay, *Security flaws induced by CBC padding: applications to
  SSL, IPSEC, WTLS*, EUROCRYPT 2002 author/proceedings PDF at
  `https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf`.
- **Pinned challenge example:** No remote challenge is pinned in v1. A case must pin its
  authorized protocol/version and local replay harness before attempting queries.

## `stream.lfsr.known-plaintext`

- **Observable signals:** Right-shift Galois LFSR source, 32-bit state words XORed with
  file blocks, and aligned known PNG header bytes.
- **Equations:** `K_i=C_i XOR P_i`; each four-byte block emits the current 32-bit state
  in big-endian order, then applies one step `out=state&1`, `state>>=1`, and conditional
  `state XOR=TapMask`.
- **Hard assumptions:** Plaintext/ciphertext alignment and big-endian word packing match
  source, enough exact keystream bits are known, and the recurrence is linear over GF(2).
- **Cheapest falsifier:** Use PNG magic/header bytes to expose initial words and test one
  exact source step against the next word.
- **Expected cost:** Low; recover the initial state from the first exposed word, derive a
  unique tap from odd transitions, verify every transition, and replay the full file.
- **Solver adaptation:** Run `assets/solver-templates/lfsr_known_plaintext.py` with
  `state-word-be`. Its six-argument legacy bitstream mode remains separately supported.
- **Failure interpretation:** A failed step points to alignment, endianness, or tap/state
  convention; do not silently switch to a Fibonacci LFSR model.
- **Proof:** Replay every state transition and ciphertext byte, validate PNG structure,
  and compare the plaintext digest with independent challenge-side evidence.
- **Primary citation:** Massey, *Shift-register synthesis and BCH decoding*, DOI
  `10.1109/TIT.1969.1054260`, 1969. Source code separately fixes the Galois convention.
- **Pinned challenge example:** BSidesSF 2026 `lfstream`,
  `BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330`,
  `lfstream/challenge/lfsr_crypt.py:L4-L45`.

## `oracle.goldwasser-micali.replication`

- **Observable signals:** The captured transcript contains 128 unknown GM ciphertexts;
  the service decrypts a submitted 128-line vector into an AES-128 key and returns a
  stable plaintext hash/certificate.
- **Equations:** Repeating captured unknown `c_i` 128 times produces a constant key whose
  bit is the original transcript bit. Compare the certificate with locally precomputed
  all-zero and all-one decrypt/hash outcomes.
- **Hard assumptions:** The captured vector order, fixed AES test ciphertext, certificate
  calculation, and source revision are exact, and at least 128 classification submissions
  are authorized.
- **Cheapest falsifier:** Repeat one captured unknown ciphertext 128 times and require its
  certificate to classify uniquely as the all-zero or all-one outcome.
- **Expected cost:** Oracle-bound; 128 classification submissions plus local certificate
  preparation and one original-transcript replay.
- **Solver adaptation:** Repeat each captured ciphertext in turn, classify its certificate,
  assemble the original 128-bit AES key in source order, then decrypt the captured payload.
- **Failure interpretation:** Indistinguishable controls block the wrapper oracle. They
  do not disprove GM or authorize factoring attempts.
- **Proof:** Replay all 128 classifications, recover the original transcript key, and
  decrypt/re-encrypt the original AES payload. Known-bit controls alone are not proof.
- **Primary citation:** Goldwasser and Micali, *Probabilistic encryption*, DOI
  `10.1016/0022-0000(84)90070-9`, 1984. The replication weakness belongs to the wrapper,
  not the paper's semantic-security claim.
- **Pinned challenge example:** BSidesSF 2026 `kproof`,
  `BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330`,
  `kproof/challenge/src/kproof.go:L64-L690`; the author route is
  `kproof/solution/solve.py:L77-L157` at the same SHA.
