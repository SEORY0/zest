# ECC and signatures

Use exact curve/domain parameters and message representatives. Apply the six
[literature and adaptation gates](../literature.md); the [catalog](../attack-cards.json)
keeps repeated, partial, and algebraically related nonce families separate.

## `signature.ecdsa.reused-nonce`

- **Observable signals:** Two or more valid ECDSA samples on one audited domain, the
  public key, and an exactly repeated `r` value.
- **Equations:** With one reused nonce,
  `k=(z1-z2)*(s1-s2)^(-1) mod q` and
  `d=(s1*k-z1)*r^(-1) mod q`.
- **Hard assumptions:** Both signatures use the same nonzero nonce in the same prime-order
  subgroup, the exact message-to-`z` rule is known, and all required inverses exist.
- **Cheapest falsifier:** Derive `k,d`, verify `x(kG) mod q=r`, `dG=Q`, and validate both
  signatures. Distinct `r` values reject exact reuse.
- **Expected cost:** Low; a constant number of modular inversions and scalar products.
- **Solver adaptation:** Use `assets/solver-templates/ecdsa_nonce_reuse.py`. Retain its
  proven-small-domain or exact secp256k1/P-256 restriction and all curve/order checks.
- **Failure interpretation:** Non-invertible differences, invalid source signatures, or
  a public-key mismatch reject this card. Test related or partial nonces separately.
- **Proof:** Verify both public signature equations, the recovered public key, and the
  nonce point; checking only the private-scalar formula is insufficient.
- **Primary citation:** NIST FIPS 186-5, *Digital Signature Standard*, DOI
  `10.6028/NIST.FIPS.186-5`, Section 6.4, 2023. The standard supplies the ECDSA
  equations and per-message-secret requirements; it is not cited as an attack paper.
- **Pinned challenge example:** Zest synthetic fixtures
  `SEORY0/zest@d22a8082aafdcba72c643b913c95b7a448b09a97`,
  `scripts/fixtures/zest-crypto/solvers/ecdsa-nonce-reuse.json` and
  `ecdsa-p256-nonce-reuse.json`.

Related routes are documented under [lattices and small roots](lattices-and-small-roots.md)
and [paper-derived constructions](paper-derived-constructions.md).
