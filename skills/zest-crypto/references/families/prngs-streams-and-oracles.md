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
  ciphertext mutation is accepted, and the case authorizes enough queries.
- **Cheapest falsifier:** Repeat eight valid controls and eight one-byte-invalid controls;
  reject noisy or indistinguishable response classes.
- **Expected cost:** Oracle-bound; at most 256 guesses per byte plus ambiguity controls,
  always below `max_oracle_queries`.
- **Solver adaptation:** Write a case-local client with deterministic guess order,
  ambiguity probes, transcript logging, timeout, and hard query counter.
- **Failure interpretation:** Instability blocks the oracle; it is not permission to add
  timing amplification or more traffic.
- **Proof:** Replay the complete transcript and independently decrypt/re-encrypt every
  recovered CBC block.
- **Primary citation:** Vaudenay, *Security flaws induced by CBC padding: applications to
  SSL, IPSEC, WTLS*, EUROCRYPT 2002 author/proceedings PDF at
  `https://iacr.org/cryptodb/archive/2002/EUROCRYPT/2850/2850.pdf`.
- **Pinned challenge example:** No remote challenge is pinned in v1. A case must pin its
  authorized protocol/version and local replay harness before attempting queries.

## `stream.lfsr.known-plaintext`

- **Observable signals:** Right-shift Galois LFSR source, 32-bit state words XORed with
  file blocks, and aligned known PNG header bytes.
- **Equations:** `K_i=C_i XOR P_i`; source step is
  `out=state&1`, `state>>=1`, and conditional `state XOR=TapMask`.
- **Hard assumptions:** Plaintext/ciphertext alignment and big-endian word packing match
  source, enough exact keystream bits are known, and the recurrence is linear over GF(2).
- **Cheapest falsifier:** Use PNG magic/header bytes to expose initial words and test one
  exact source step against the next word.
- **Expected cost:** Low for a 32-variable GF(2) solve and full-file replay. The bundled
  exhaustive template is intentionally limited to toy widths no greater than 12.
- **Solver adaptation:** Validate direction/bit order with
  `assets/solver-templates/lfsr_known_plaintext.py`, then replace toy exhaustive search
  with a bounded linear recurrence/state solve for the 32-bit instance.
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

- **Observable signals:** A service accepts 128 attacker-selected valid GM bit
  ciphertexts, decrypts them independently into an AES-128 key, and reveals a stable
  application-level acceptance/error class.
- **Equations:** A valid encryption of zero is `c=y^2 mod n`; a valid encryption of one
  is `c=x*y^2 mod n`. Repeating the same valid `c` 128 times produces an all-zero or
  all-one decrypted key.
- **Hard assumptions:** `gcd(y,n)=1`, public `n,x` are used exactly, chosen ciphertexts
  are authorized, and a payload encrypted under the forced key reaches a distinguishable
  wrapper result.
- **Cheapest falsifier:** Submit one all-zero-key and one all-one-key control transcript,
  each with a locally matching AES-CBC payload.
- **Expected cost:** Oracle-bound; two 128-line controls and only the separately declared
  follow-up query budget.
- **Solver adaptation:** Generate valid GM ciphertexts locally, replicate rather than
  malform them, construct the matching AES payload, and log every submitted line and
  service response.
- **Failure interpretation:** Indistinguishable controls block the wrapper oracle. They
  do not disprove GM or authorize factoring attempts.
- **Proof:** Verify public GM construction for every line, replay the AES payload under
  the forced key, and reproduce both response classes.
- **Primary citation:** Goldwasser and Micali, *Probabilistic encryption*, DOI
  `10.1016/0022-0000(84)90070-9`, 1984. The replication weakness belongs to the wrapper,
  not the paper's semantic-security claim.
- **Pinned challenge example:** BSidesSF 2026 `kproof`,
  `BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330`,
  `kproof/challenge/src/kproof.go:L64-L133,L511-L690`.
