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
  `HITCON CTF 2024/MatProd/dist/chall.py:L6-L60` for the construction and
  `chall.py:L199-L228` for the concrete direct/alternating parameters and serialized output.

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
  `HITCON CTF 2024/Hyper512/dist/chall.py:L4-L64`.

## `paper.ecdsa.lcg-nonce`

- **Observable signals:** The pinned set of 17 aligned ECDSA signatures whose integer
  nonce states evolve modulo a 311-bit `p` but are observed modulo secp256k1 order `q`,
  with `p!=q`.
- **Equations:** Adjacent ECDSA equations expose nonce differences modulo `q`; short
  integer-orthogonal vectors bridge those residues to bounded LCG states modulo `p`.
- **Hard assumptions:** The source proves `p!=q`; all 17 signatures are present; the
  author projection uses `n=14`, `t=4`; `||lambda||_1*2^high_bits <
  2^(lcg_bits*(1-1/t))` is explicitly verified; and a faithful cross-modulus toy instance
  recovers a known `d`. Four generic recurrence samples do not satisfy this pinned route.
- **Cheapest falsifier:** On a reduced `p!=q` instance recover one orthogonal vector,
  reconstruct `p` and the LCG multiplier, and replay both modulus layers.
- **Expected cost:** High; the pinned `n=14`, `t=4` orthogonal-lattice stage after its
  checked Stern bound, resultants, a polynomial gcd, and one bounded mixed-modulus lattice.
- **Solver adaptation:** Follow the author route: derive adjacent nonce-difference
  vectors, recover `p` via resultants and `a` via polynomial gcd, then solve the bounded
  mixed-modulus lattice for `d`. Never apply the recurrence directly modulo `q`.
- **Failure interpretation:** A failed recurrence equation rejects the mapping. Repeated
  `r` values route first to exact nonce reuse.
- **Proof:** Verify `dG=Q`, integer states modulo `p`, their ECDSA reductions modulo `q`,
  and every lift bound.
- **Primary citation:** Bellare, Goldwasser, and Micciancio, *Pseudo-random generators
  within cryptographic applications: the DSS case* (CRYPTO 1997) is a DSS theorem only.
  Macchetti, *A novel related nonce attack for ECDSA*, ePrint `2023/305`, covers the
  generic same-modulus family. ECLCG's `p!=q` orthogonal/Stern bridge comes from its
  pinned author solution and must be stated separately.
- **Pinned challenge example:** HITCON CTF 2024 ECLCG,
  `maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6`,
  `HITCON CTF 2024/ECLCG/dist/chall.py:L25-L64`, `README.md:L21-L90`, and
  `solution/solve_lance_roy.sage:L8-L50` for the exact projection and bound.

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
- **Pinned challenge example:** HITCON CTF 2025 Paranoid,
  `maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6`,
  `HITCON CTF 2025/Paranoid/README.md:L15-L31`, explicitly supplies one independent list
  per round. Pedantic is only a variant/negative example: its fixed LCG author route uses
  a fixed point plus affine CVP/LLL. MAT347 is also negative because its queries are adaptive.

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
  `crypto/law-and-order/challenge/app/chall.py:L150-L311`.

## `paper.uov.wrapper-structure`

- **Observable signals:** Seven 112-byte signature components and seven UOV public maps.
- **Equations:** The exact verifier is
  `XOR_i PubMap_i(sig_i)=SHAKE256(msg,44)`.
- **Hard assumptions:** The exact public maps and parser are pinned, a reduced verifier
  replays, and a concrete source-faithful exploit invariant is separately proved. Honest
  toy signing is not an exploit invariant.
- **Cheapest falsifier:** Evaluate all seven maps, XOR their 44-byte outputs, and compare
  with the exact SHAKE256 target.
- **Expected cost:** At most 65536 explicitly justified candidate trials. Without a
  concrete exploit identity, the card remains blocked rather than inventing rank algebra.
- **Solver adaptation:** Build the exact verifier and bound any candidate search, but do
  not claim linear/triangular structure unless it is derived and independently verified.
- **Failure interpretation:** The pinned zero-solve source has no author solution; absent
  a verified invariant, this route stays blocked.
- **Proof:** Evaluate every `PubMap_i`, XOR all outputs, and match SHAKE256(msg,44).
- **Primary citation:** Kipnis, Patarin, and Goubin, *Unbalanced Oil and Vinegar signature
  schemes*, DOI `10.1007/3-540-48910-X_15`, 1999, defines UOV. Wrapper structure remains
  a challenge observation.
- **Pinned challenge example:** SekaiCTF 2025 unfairy-ring,
  `project-sekai-ctf/sekaictf-2025@683dd81ae520581add40ec21c4819866e28cbde4`,
  `crypto/unfairy-ring/dist/chall.py:L10-L18`.

## `paper.csidh.auxiliary-point-leak`

- **Observable signals:** A curve-plus-point public key where the base point has order
  `p+1` and each selected `ell`-isogeny removes `ell` from the transported point order.
- **Equations:** Compute `cf=(p+1)/ord(G_pub)` and set support bit
  `e_i=1 iff ell_i divides cf` for each of 128 small primes.
- **Hard assumptions:** Exponents lie in `{-1,0,1}` and the source defect makes sign
  immaterial, so the support vector reproduces the public action.
- **Cheapest falsifier:** Compute one point order and verify all 128 divisibility bits by
  replaying both published curve-plus-point tuples.
- **Expected cost:** One point-order computation, 128 divisibility tests, one bounded
  action replay, and one shared-secret derivation; no backtracking.
- **Solver adaptation:** Recover the support vector, replay it, derive `j(E)+x(G)`, then
  derive the AES key and decrypt the ciphertext.
- **Failure interpretation:** Curve-only public keys reject this wrapper card. A failed
  point invariant says nothing about standard CSIDH hardness.
- **Proof:** Reapply the recovered action and reproduce every curve coefficient, point,
  shared invariant, and ciphertext-key relation.
- **Primary citation:** Castryck, Lange, Martindale, Panny, and Renes, *CSIDH: An efficient
  post-quantum commutative group action*, ePrint `2018/383`, defines the construction.
  The auxiliary leak is challenge-derived.
- **Pinned challenge example:** ImaginaryCTF 2024 coast,
  `maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6`,
  `ImaginaryCTF 2024/coast/README.md:L11-L15`, `coast/chall.sage:L6-L16`,
  `coast/solve.sage:L7-L17`, and the recovery at `coast/solve.sage:L52-L69`.

## `symmetric.slide.periodic-round`

- **Observable signals:** `tc_demo.py` exposes chosen 16-round encryption and a 1024-round
  flag target; the core is 24-bit with a 16-bit Feistel subkey and 24x24 affine layer.
- **Equations:** Encryption applies `x=F(x XOR c)` per chunk; inversion is
  `state=F^-1(state) XOR c` in reverse counter order.
- **Hard assumptions:** Both service and core sources are pinned, at least 25 independent
  augmented pairs exist (the author solver uses 64), and the affine system has full rank.
- **Cheapest falsifier:** Brute-force the 16-bit subkey, solve the affine map, and require
  every held-out 16-round pair to replay before targeting the flag.
- **Expected cost:** 64 chosen pairs, at most `2^16` subkey guesses, one 24x24 affine
  solve, and exactly 64 inverse chunks for the 1024-round flag.
- **Solver adaptation:** Recover the subkey, recover the affine layer and constant, then
  apply `F^-1(state) XOR c` over all 64 chunks.
- **Failure interpretation:** Failed normalization rejects the slide card; repeated source
  code alone is not evidence. Do not compensate with an unbounded codebook.
- **Proof:** Reproduce all held-out 16-round pairs, invert 64 target chunks, and re-encrypt
  the recovered flag through the exact 1024-round wrapper.
- **Primary citation:** Biryukov and Wagner, *Advanced slide attacks*, DOI
  `10.1007/3-540-45539-6_41`, EUROCRYPT 2000, author/proceedings PDF
  `https://www.iacr.org/archive/eurocrypt2000/1807/18070595-new.pdf`.
- **Pinned challenge example:** BSidesSF 2026 tokencrypt,
  `BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330`,
  `tokencrypt/challenge/src/tc_demo.py:L12-L175` and
  `tokencrypt/challenge/src/tokencrypt.py:L11-L326`; the exact `2^16` search, 25-vector
  affine solve, and inverse are in `tokencrypt/solution/recover_round.py:L134-L178`.

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
  `rotor-cipher/rotor_cipher.py:L46-L149`.
- **Pinned challenge example:** UofTCTF 2026 Rotor Cipher at that immutable source. The
  catalog maps the observed permutation equations to group conjugacy without claiming an
  external theorem about this wrapper.
