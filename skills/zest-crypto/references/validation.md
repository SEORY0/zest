# Proof requirements

A recovered value is verified only with evidence appropriate to the construction.
Save the command, inputs, and result under `case/proof/`.

- **Equation proof:** recompute the public relation exactly, such as a signature,
  factorization, congruence, group relation, or ciphertext equation.
- **Round-trip proof:** decrypt and re-encrypt, regenerate a PRNG output, or run the
  reversible pipeline in both directions.
- **Verifier proof:** run the supplied or independently reconstructed verifier against
  all relevant samples.
- **Transcript-replay proof:** replay an oracle transcript against a local harness or
  an authorized endpoint and confirm each response class.
- **Exact-file-digest proof:** compare a derived artifact to its expected SHA-256
  digest when the challenge supplies one.

Flag shape and printability are supporting evidence only. They never establish a
solve without one of the proofs above, or another exact construction-specific
check recorded in the case.
