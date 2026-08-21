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
- **Local package example:** `assets/solver-templates/coppersmith_univariate.sage:L1-L207`.

## `signature.ecdsa.partial-nonce-hnp`

- **Observable signals:** Valid ECDSA samples, public key, sample count, subgroup order,
  and either exact MSB/LSB leakage or a measured bias that matches a named bias model.
- **Equations:** From `s_i*k_i=z_i+r_i*d mod q`, normalize the known nonce part to a
  modular approximation of `d`; encode the bounded errors in one documented HNP lattice.
- **Hard assumptions:** Record `known-bits` or `eprint-2019-023-bias`, the MSB/LSB or
  centered-bias orientation, and a derived parameter-bound proof combining sample count,
  leak/bias size, group size, independence, and lattice embedding. There is no universal
  four-sample floor, and known bits are not interchangeable with arbitrary positive bias.
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
- **Primary citations:** Nguyen and Shparlinski, *The insecurity of the elliptic curve
  digital signature algorithm with partially known nonces*, DOI
  `10.1023/A:1025436905711`, 2003, for known-bit models; Breitner and Heninger, ePrint
  `2019/023`, only for bias instances matching that paper's stated model.
- **Pinned challenge example:** No external mapping is asserted in v1. Pin the leakage
  extraction code and exact message-to-`z` conversion before making this card eligible.

## `lattice.subset-sum.query-schedule`

- **Observable signals:** A stateful oracle whose sign query adds `1+h(m)` to a hidden
  counter, whose exchange query adds `1`, and whose custom signatures satisfy
  `s=z*k^-1+x*r mod q`, hence `k*(s-x*r)=z`.
- **Equations:** For MAT347, record every transition
  `cnt_{j+1}=cnt_j+1+a_j*h(m_j) mod 2^256`, map each signature nonce to
  `h(str(cnt_j))`, derive the exact binary subset equation, and never substitute the
  standard ECDSA equation `s*k=z+x*r`.
- **Hard assumptions:** Query order is controllable within 670 operations, all transcript
  entries are aligned, the schedule-derived relation is exact, and a faithful reduced
  transcript recovers its known subset.
- **Cheapest falsifier:** Replay a short known-counter schedule and verify every counter,
  nonce, signature, and subset equation before collecting a large transcript.
- **Expected cost:** High; at most 670 authorized queries, one fixed lattice dimension,
  one reduction schedule, and bounded nearest-vector enumeration.
- **Solver adaptation:** Find a bounded multiset of sign increments plus exchanges that
  wraps the 256-bit counter to the first-signature state, reuse that nonce for the final
  exchange, and test both `R=±lift_x(r)` using `S=(sR-zG)*r^-1`. Keep transcript capture
  separate from reduction and stop at the case query/time bounds.
- **Failure interpretation:** A failed reduced replay rejects the schedule derivation.
  A failed lattice may reflect density/scaling; it does not authorize a new query model.
- **Proof:** Replay the exact schedule, verify every `k*(s-x*r)=z` equation, reproduce
  the accepted lifted-point shared secret, and decrypt/re-encrypt the exchange ciphertext.
- **Primary citation:** Challenge-derived from UofTCTF 2026 MAT347 at
  `UofTCTF/uoftctf-2026-chals-public@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac`,
  `mat347/dist/chall.py:L24-L55`. No generic subset-sum theorem is attributed to it.
- **Pinned challenge example:** The same immutable MAT347 source. Naive Wagner routing is
  explicitly rejected: adaptive sequential queries are not independent `k` lists.
