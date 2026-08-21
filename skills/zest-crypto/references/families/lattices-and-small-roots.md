# Lattices and small roots

Apply the six [literature and adaptation gates](../literature.md). A visible `LLL` or
`small_roots` token is only a ranking signal; the [catalog](../attack-cards.json)
requires a concrete equation, sufficient bound, and faithful reduced check.

## `lattice.coppersmith.univariate-small-root`

- **Observable signals:** Exact univariate polynomial, modulus, positive root bound,
  monic/invertible-leading-coefficient evidence, and a successful reduced invariant.
- **Equations:** Find `x0` with `f(x0)=0 mod B`, where `B` is the cited divisor of `N`;
  for the full-modulus monic degree-`d` case, the classical sufficient magnitude is
  `|x0|<N^(1/d)`.
- **Hard assumptions:** The polynomial is genuinely univariate and monic after a valid
  normalization, and the chosen `X`, `beta`, degree, and divisor claim satisfy the cited
  theorem. The sufficient bound is not claimed necessary.
- **Cheapest falsifier:** Re-evaluate a known toy root in the original integer polynomial,
  reject non-monic/non-invertible normalization, and compare the proposed bound with the
  theorem before invoking reduction.
- **Expected cost:** High; one Sage `small_roots` run with degree at most 16, bounded `X`,
  beta denominator at most 64, and a returned-root cap.
- **Solver adaptation:** Use `assets/solver-templates/coppersmith_univariate.sage`; map
  coefficients in ascending order and preserve its original-congruence divisor proof.
- **Failure interpretation:** No root under one parameter set rejects that attempt, not
  every Coppersmith construction. A multivariate polynomial is unsupported by this card.
- **Proof:** Check strict root magnitude and the original polynomial/divisor relation for
  every returned integer.
- **Primary citation:** Coppersmith, *Finding a small root of a univariate modular
  equation*, DOI `10.1007/3-540-68339-9_14`, EUROCRYPT 1996.
- **Pinned challenge example:** Zest synthetic fixture
  `SEORY0/zest@d22a8082aafdcba72c643b913c95b7a448b09a97`,
  `scripts/fixtures/zest-crypto/solvers/coppersmith-univariate.json`.

## `signature.ecdsa.partial-nonce-hnp`

- **Observable signals:** Valid ECDSA samples, public key, exact MSB/LSB leakage or a
  quantified nonce bias/error bound, sample count, and subgroup order.
- **Equations:** From `s_i*k_i=z_i+r_i*d mod q`, normalize the known nonce part to a
  modular approximation of `d`; encode the bounded errors in one documented HNP lattice.
- **Hard assumptions:** Leakage orientation and bounds are correct, samples are aligned
  and sufficiently independent, and their number versus leakage satisfies the selected
  result. Any leakage is necessary evidence but not sufficient recovery evidence.
- **Cheapest falsifier:** Derive all approximations symbolically and recover a known key
  in a reduced instance with the same bit orientation and lattice scaling.
- **Expected cost:** High; one stated LLL/BKZ schedule and a bounded closest-vector or
  short-vector neighborhood.
- **Solver adaptation:** Build a Sage solver around the exact signature equations; state
  the lattice basis, target, scale, reduction block size, retries, and enumeration cap.
- **Failure interpretation:** Failed recovery may mean insufficient samples, wrong leak
  direction/bound, or inadequate reduction. It does not validate nonce security.
- **Proof:** Check `dG=Q`, every signature, and every reconstructed nonce against the
  claimed leak or bias interval.
- **Primary citation:** Nguyen and Shparlinski, *The insecurity of the elliptic curve
  digital signature algorithm with partially known nonces*, DOI
  `10.1023/A:1025436905711`, 2003.
- **Pinned challenge example:** No external mapping is asserted in v1. Pin the leakage
  extraction code and exact message-to-`z` conversion before making this card eligible.

## `lattice.subset-sum.query-schedule`

- **Observable signals:** A stateful oracle whose sign query adds `1+h(m)` to a hidden
  counter, whose exchange query adds `1`, and whose later ECDSA/ECDH values preserve an
  exact modular subset-sum relation across an authorized schedule.
- **Equations:** For MAT347, record every transition
  `cnt_{j+1}=cnt_j+1+a_j*h(m_j) mod 2^256`, map each signature nonce to
  `h(str(cnt_j))`, and derive the exact binary subset equation used by the lattice.
- **Hard assumptions:** Query order is controllable within 670 operations, all transcript
  entries are aligned, the schedule-derived relation is exact, and a faithful reduced
  transcript recovers its known subset.
- **Cheapest falsifier:** Replay a short known-counter schedule and verify every counter,
  nonce, signature, and subset equation before collecting a large transcript.
- **Expected cost:** High; at most 670 authorized queries, one fixed lattice dimension,
  one reduction schedule, and bounded nearest-vector enumeration.
- **Solver adaptation:** Implement the schedule first, then build the modular subset-sum
  lattice from recorded hash increments and signature equations. Keep transcript capture
  separate from reduction and stop at the case query/time bounds.
- **Failure interpretation:** A failed reduced replay rejects the schedule derivation.
  A failed lattice may reflect density/scaling; it does not authorize a new query model.
- **Proof:** Replay the exact schedule, verify all signatures, derive the exchange nonce,
  reproduce its ECDH point/key/IV, and decrypt/re-encrypt the ciphertext.
- **Primary citation:** Challenge-derived from UofTCTF 2026 MAT347 at
  `UofTCTF/uoftctf-2026-chals-public@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac`,
  `mat347/dist/chall.py:L24-L55`. No generic subset-sum theorem is attributed to it.
- **Pinned challenge example:** The same immutable MAT347 source. Naive Wagner routing is
  explicitly rejected: adaptive sequential queries are not independent `k` lists.
