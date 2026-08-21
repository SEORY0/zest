# ECC and signatures

Use exact curve/domain parameters and message representatives. Apply the six
[literature and adaptation gates](../literature.md); the [catalog](../attack-cards.json)
keeps repeated, partial, and algebraically related nonce families separate.

## `signature.ecdsa.reused-nonce`

- **Observable signals:** Two or more valid ECDSA samples on one audited domain, the
  public key, and an exactly repeated `r` value.
- **Equations:** Let `epsilon=1` when the second nonce is `k` and `epsilon=-1`
  when it is `q-k`. Then
  `k=(z1-z2)*(s1-epsilon*s2)^(-1) mod q` and
  `d=(s1*k-z1)*r^(-1) mod q`; the two denominators are `s1-s2` and `s1+s2`.
- **Hard assumptions:** Both signatures arise from nonce points with the same x-coordinate
  in one prime-order subgroup, the exact message-to-`z` rule is known, and all required
  inverses exist. Equal `r` can represent nonce scalars `k` and `q-k`.
- **Cheapest falsifier:** Try both `s2` and `-s2 mod q`, derive each candidate `k,d`,
  verify `x(kG) mod q=r`, `dG=Q`, and validate both signatures. This also rejects equal-r
  collisions that do not share either nonce sign.
- **Expected cost:** Low; a constant number of modular inversions and scalar products.
- **Solver adaptation:** Use `assets/solver-templates/ecdsa_nonce_reuse.py`. Retain its
  proven-small-domain or exact secp256k1/P-256 restriction and all curve/order checks.
- **Failure interpretation:** Non-invertible differences, invalid source signatures,
  failed `k`/`q-k` variants, or a public-key mismatch reject this card. Test related or
  partial nonces separately.
- **Proof:** Report the selected same/opposite relation and signs, verify both original
  public signature equations, prove `dG=Q`, and prove each signed nonce scalar reproduces
  its exact verifier point; checking only the private-scalar formula is insufficient.
- **Primary citation:** NIST FIPS 186-5, *Digital Signature Standard*, DOI
  `10.6028/NIST.FIPS.186-5`, Section 6.4, 2023. The standard supplies the ECDSA
  equations and per-message-secret requirements; it is not cited as an attack paper.
- **Local package example:** `assets/solver-templates/ecdsa_nonce_reuse.py:L1-L344`.

Related routes are documented under [lattices and small roots](lattices-and-small-roots.md)
and [paper-derived constructions](paper-derived-constructions.md).
