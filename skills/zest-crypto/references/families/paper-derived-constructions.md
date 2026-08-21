# Paper-derived and challenge-wrapper constructions

Use the six [literature and adaptation gates](../literature.md). The
[catalog](../attack-cards.json) separates paper claims from source observations; a
challenge title or citation token can rank a card but cannot satisfy its hard gates.

## `paper.matrix-product.trace-lattice`

- **Observable signals:** Ordered products of public matrices over `F_p`, ePrint
  2023/1745 construction identifiers, ePrint 2024/1332 attack identifiers, and a
  source-mapped trace, determinant, or characteristic-polynomial invariant.
- **Equations:** Use only the exact invariant derived in ePrint 2024/1332 for the
  selected blueprint. `tr(AB)=tr(BA)` may help eliminate product order in the stated
  cases; it is not a universal recovery theorem.
- **Hard assumptions:** Challenge matrices instantiate the attacked blueprint and the
  chosen invariant maps to its public/secret variables. A reduced instance reproduces
  the same leak.
- **Cheapest falsifier:** Compute the claimed invariant on a small source-faithful product
  and reject generic matrix-algebra routing if it does not distinguish the hidden data.
- **Expected cost:** High; one dimension/field-bounded Sage model and only the lattice or
  enumeration derived from the exact attack.
- **Solver adaptation:** Map blueprint symbols first, then implement the 2024 attack.
  Record matrix dimension, field, coefficient bounds, lattice dimension, and candidate cap.
- **Failure interpretation:** A failed invariant rejects this route for the mapped variant;
  it does not establish the security conjectures of the blueprint.
- **Proof:** Reconstruct the ordered product/trapdoor output and every public matrix,
  trace, determinant, characteristic-polynomial, and ciphertext relation used.
- **Primary citation:** Geraud-Stewart and Naccache, ePrint `2023/1745`, defines the
  blueprints. Decru, Fouotsa, Frixons, Gilchrist, and Petit, *Attacking trapdoors from
  matrix products*, ePrint `2024/1332`, supplies the attack. `trace-lattice` is only this
  catalog's routing label.
- **Pinned challenge example:** HITCON CTF 2024 MatProd,
  `maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6`,
  `HITCON CTF 2024/MatProd/dist/chall.py`.

## `paper.stream-cipher.fca-lwpm`

- **Observable signals:** Known feedback polynomial over `F_2`, bounded available
  keystream, a measured correlation model, and an exact low-weight-polynomial-multiple
  construction.
- **Equations:** Find `g=f*h` over `F_2[X]` with bounded degree and Hamming weight; each
  verified multiple supplies the parity relation used by the separately modeled fast
  correlation stage.
- **Hard assumptions:** Polynomial and bit ordering are exact, the degree bound fits the
  available stream, and the resulting weight/bias make the declared correlation work
  feasible.
- **Cheapest falsifier:** On a reduced recurrence, verify divisibility, weight, constant
  term where required, and the predicted parity bias on held-out stream bits.
- **Expected cost:** High; one bounded LWPM lattice plus a separately bounded decoding
  stage. Plain FCA without a feasible multiple is rejected.
- **Solver adaptation:** Implement ePrint 2007/423 over the exact polynomial; validate
  every short vector as a polynomial multiple before feeding it to the correlation solver.
- **Failure interpretation:** No useful vector within the degree/dimension cap rejects
  that LWPM attempt; a wrong measured bias rejects the family mapping.
- **Proof:** Recheck divisibility/weight exactly, recover a state or key, and replay all
  held-out keystream bits.
- **Primary citation:** El Aimani and von zur Gathen, *Finding low weight polynomial
  multiples using lattices*, ePrint `2007/423`, 2007.
- **Pinned challenge example:** HITCON CTF 2024 Hyper512,
  `maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6`,
  `HITCON CTF 2024/Hyper512/dist/chall.py`.

## `paper.ecdsa.lcg-nonce`

- **Observable signals:** At least four aligned ECDSA signatures, an exact modular nonce
  recurrence, ePrint 2023/305, and pinned source showing how nonces enter signing.
- **Equations:** For every sample,
  `k_i=(z_i+r_i*d)*s_i^(-1) mod q`; substitute these affine functions of `d` into the
  observed LCG or higher-degree recurrence and eliminate unknown recurrence coefficients.
- **Hard assumptions:** Signatures are valid, recurrence/order/sample count match the
  selected elimination, and a faithful toy instance recovers a known `d`.
- **Cheapest falsifier:** Substitute toy signatures into the exact recurrence and demand
  that the resulting polynomial has the known private scalar as a root.
- **Expected cost:** High; one bounded finite-field polynomial-root or lattice stage with
  degree/dimension derived from recurrence and sample count.
- **Solver adaptation:** Implement the ePrint 2023/305 ECDSA equations, solve only the
  declared polynomial degree, and verify every candidate against public key and recurrence.
- **Failure interpretation:** A failed recurrence equation rejects the mapping. Repeated
  `r` values route first to exact nonce reuse.
- **Proof:** Verify `dG=Q`, every ECDSA signature, and every reconstructed nonce transition.
- **Primary citation:** Bellare, Goldwasser, and Micciancio, *Pseudo-random generators
  within cryptographic applications: the DSS case* (CRYPTO 1997) is a DSS theorem only.
  Macchetti, *A novel related nonce attack for ECDSA*, ePrint `2023/305`, supplies the
  ECDSA mapping. The lift obligation must be written, never implied.
- **Pinned challenge example:** HITCON CTF 2024 ECLCG,
  `maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6`,
  `HITCON CTF 2024/ECLCG/dist/chall.py`.

## `paper.wagner.generalized-birthday`

- **Observable signals:** `k` independent lists, a specified XOR or modular-sum target,
  a balanced merge/filter schedule, and the Wagner paper identifier.
- **Equations:** Select one `x_i` per independent list with
  `x_1 XOR ... XOR x_k=0` or the explicitly mapped group target; intermediate merges
  filter a stated number of bits while retaining bounded candidates.
- **Hard assumptions:** List independence, distribution, operation, sizes, and target all
  match the merge tree; a reduced four-list instance succeeds.
- **Cheapest falsifier:** Run the bundled four-list exact-sum toy and verify the original
  target from one selected value per list.
- **Expected cost:** High; list lengths, merge levels, filtered bits, collision cap, and
  memory are fixed before execution.
- **Solver adaptation:** Start with
  `assets/solver-templates/wagner_generalized_birthday.py`; for more lists, add a balanced
  tree without weakening independence or the original target proof.
- **Failure interpretation:** An empty merge may be a sizing issue. Adaptive dependent
  choices are a family mismatch, not a reason to tune list sizes.
- **Proof:** Recompute the original group relation from the selected source-list elements.
- **Primary citation:** Wagner, *A generalized birthday problem*, CRYPTO 2002, DOI
  `10.1007/3-540-45708-9_19`, proceedings PDF
  `https://www.iacr.org/archive/crypto2002/24420288/24420288.pdf`.
- **Pinned challenge example:** HITCON CTF 2025 Pedantic,
  `maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6`,
  `HITCON CTF 2025/Pedantic/src/server.py`. MAT347 is a negative example: its adaptive
  query schedule explicitly rejects naive independent-list routing.

## `paper.frost.threshold-signature`

- **Observable signals:** Threshold Schnorr transcript, participant commitments, binding
  factors, Lagrange coefficients, signing shares, and ePrint 2020/852.
- **Equations:** Recompute each share equation and the aggregate Schnorr equation using
  the paper's participant set, commitment list, binding factors, and group challenge.
- **Hard assumptions:** Domain, identifiers, transcript encoding, and participant set are
  exact, and a reduced transcript passes every share equation.
- **Cheapest falsifier:** Validate every public share equation. Ordinary single-party
  Schnorr or ECDSA is rejected.
- **Expected cost:** Medium for transcript verification; any exploit search needs a
  separately observed and bounded wrapper deviation.
- **Solver adaptation:** Implement the construction faithfully, then isolate only source-
  observed nonce reuse, participant substitution, missing validation, or encoding behavior.
- **Failure interpretation:** Invalid shares reject the transcript mapping. Valid FROST
  behavior is not evidence of vulnerability.
- **Proof:** Verify all shares, the aggregate signature, and the exact wrapper condition
  used for any forgery or secret recovery.
- **Primary citation:** Komlo and Goldberg, *FROST: Flexible round-optimized Schnorr
  threshold signatures*, ePrint `2020/852`, 2020. It is a construction/security proof,
  not a generic exploit paper.
- **Pinned challenge example:** SekaiCTF 2025 law-and-order,
  `project-sekai-ctf/sekaictf-2025@683dd81ae520581add40ec21c4819866e28cbde4`,
  `crypto/law-and-order/challenge/app/chall.py`.

## `paper.uov.wrapper-structure`

- **Observable signals:** UOV public quadratic maps plus source-observed key reuse,
  ring/XOR composition, or another wrapper relation not present in bare UOV.
- **Equations:** Write the exact public maps and derive only identities following from
  degree two and the observed wrapper, such as controlled differences or rank/triangular
  relations.
- **Hard assumptions:** Field, dimensions, public maps, wrapper combination, and verifier
  are exact; a reduced wrapper accepts a generated toy witness.
- **Cheapest falsifier:** Evaluate a toy UOV map and wrapper, compute the proposed
  difference/rank relation, and run the wrapper verifier.
- **Expected cost:** High; finite-field dimension, rank work, free-variable trials, and
  verifier calls are bounded before Sage execution.
- **Solver adaptation:** Build maps in Sage, reduce the source-derived identities to
  bounded linear/triangular solves, and enumerate only a stated free-variable budget.
- **Failure interpretation:** A failed wrapper identity rejects the challenge-derived
  route; it makes no claim about generic UOV security.
- **Proof:** Evaluate every original public map and complete wrapper acceptance predicate.
- **Primary citation:** Kipnis, Patarin, and Goubin, *Unbalanced Oil and Vinegar signature
  schemes*, DOI `10.1007/3-540-48910-X_15`, 1999, defines UOV. Wrapper structure remains
  a challenge observation.
- **Pinned challenge example:** SekaiCTF 2025 unfairy-ring,
  `project-sekai-ctf/sekaictf-2025@683dd81ae520581add40ec21c4819866e28cbde4`,
  `crypto/unfairy-ring/dist/chall.py`.

## `paper.csidh.auxiliary-point-leak`

- **Observable signals:** CSIDH-like class-group action plus an extra point transported
  through the secret action and printed with the public curve.
- **Equations:** Reproduce the exact isogeny action on curve and point, then derive the
  source-observed point-order/eigenspace relation used to distinguish secret exponents.
- **Hard assumptions:** Curve parameters, prime list, exponent domain, point transport,
  and invariant are exact; a small-parameter action reproduces the leak.
- **Cheapest falsifier:** Transport known auxiliary points through small actions and test
  the claimed order/eigenspace observation.
- **Expected cost:** High; bound prime count, exponent interval, isogeny steps, order
  tests, and backtracking nodes.
- **Solver adaptation:** Partition/search the secret action only by proven auxiliary-point
  behavior and verify candidates against both published curves and points.
- **Failure interpretation:** Curve-only public keys reject this wrapper card. A failed
  point invariant says nothing about standard CSIDH hardness.
- **Proof:** Reapply the recovered action and reproduce every curve coefficient, point,
  shared invariant, and ciphertext-key relation.
- **Primary citation:** Castryck, Lange, Martindale, Panny, and Renes, *CSIDH: An efficient
  post-quantum commutative group action*, ePrint `2018/383`, defines the construction.
  The auxiliary leak is challenge-derived.
- **Pinned challenge example:** ImaginaryCTF 2024 coast,
  `maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6`,
  `ImaginaryCTF 2024/coast/chall.sage`.

## `symmetric.slide.periodic-round`

- **Observable signals:** Repeated keyed 16-round Feistel-plus-affine chunk, public chunk
  index XOR before each chunk, chosen-input surface, and a tested normalized relation.
- **Equations:** Source defines `G_c(x)=Chunk(x XOR c)` and
  `E(x)=G_(r-1)(...G_1(G_0(x)))`. Derive and test a relation across `G_c,G_(c+1)`; do
  not replace it with unsupported `E=Chunk^r`.
- **Hard assumptions:** Counter wrapper, affine layer, round core, chunk count, and
  chosen-input behavior are exact; a reduced-key/block model confirms the relation.
- **Cheapest falsifier:** Test two adjacent normalized chunks on a reduced model. A bare
  repeated-round match that ignores `x XOR c` is explicitly rejected.
- **Expected cost:** High; chosen texts, 24-bit table entries, candidate pairs, memory,
  and key checks are fixed before execution.
- **Solver adaptation:** Implement the resolved source exactly, derive normalized slid-
  pair filters, recover candidate chunk parameters under caps, and replay full encryption.
- **Failure interpretation:** Failed normalization rejects the slide card; repeated source
  code alone is not evidence. Do not compensate with an unbounded codebook.
- **Proof:** Reproduce held-out chosen pairs and complete encrypt/decrypt results for every
  tested round count including the counter wrapper.
- **Primary citation:** Biryukov and Wagner, *Advanced slide attacks*, DOI
  `10.1007/3-540-45539-6_41`, EUROCRYPT 2000, author/proceedings PDF
  `https://www.iacr.org/archive/eurocrypt2000/1807/18070595-new.pdf`.
- **Pinned challenge example:** BSidesSF 2026 tokencrypt,
  `BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330`,
  `tokencrypt/distfiles/tokencrypt.py:L1`, resolved at the same SHA to
  `tokencrypt/challenge/src/tokencrypt.py:L11-L19,L300-L326`.

## `symmetric.rotor.group-conjugacy`

- **Observable signals:** Known symbol mappings under recorded rotor order, initial
  positions, plugboard and stepping; source represents components as permutation matrices.
- **Equations:** Derive the exact composed permutation and conjugacy equations from the
  source's plugboard, forward rotors, reflector, inverse rotors, and final plugboard.
- **Hard assumptions:** Rotate-before-encrypt convention, order, positions, involutions,
  and log alignment are exact; a reduced six-symbol model has a unique conjugator.
- **Cheapest falsifier:** Enumerate at most `6!` toy conjugators and require one to satisfy
  all training equations plus independent replay mappings.
- **Expected cost:** High for the 26-symbol case; use cycle structure and known mappings
  with bounded branching, never factorial enumeration.
- **Solver adaptation:** Validate algebra with
  `assets/solver-templates/rotor_group_conjugacy.py`, then constrain 26-symbol cycles and
  replay every held-out mapping in the original implementation.
- **Failure interpretation:** Multiple toy conjugators mean insufficient observations;
  a failed replay means the stepping/order mapping is wrong. Frequency-only routing is
  a named false friend.
- **Proof:** Verify bijections and involutions, every conjugacy equation, every log mapping,
  and final wiring in the challenge implementation.
- **Primary citation:** The canonical source is challenge code, not an attack paper:
  `UofTCTF/uoftctf-2026-chals-public@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac`,
  `rotor-cipher/rotor_cipher.py:L46-L103,L107-L149`.
- **Pinned challenge example:** UofTCTF 2026 Rotor Cipher at that immutable source. The
  catalog maps the observed permutation equations to group conjugacy without claiming an
  external theorem about this wrapper.
