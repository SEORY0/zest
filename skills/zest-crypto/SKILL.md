---
name: zest-crypto
description: Analyze and solve math-heavy or paper-derived CTF cryptography involving RSA, ECC, lattices, signatures, PRNGs, stream ciphers, custom constructions, or crypto oracles. Use for attack selection, solver adaptation, and proof; route ordinary encoding-only blobs to zest-ctf.
---

# Zest Crypto

Use this skill for mathematical cryptanalysis with evidence and a reproducible
proof. For an encoding-only blob or known-parameter byte transform, use
`zest-ctf` instead.

## Core loop

1. Create a fresh case directory and hash every input before analysis.
2. Run `fingerprint.py`, or record the same facts manually when it is unavailable.
3. Validate and rank local AttackCards; do not let a score override a hard precondition.
4. Probe the highest eligible cards cheaply before starting an expensive solver.
5. Use primary-source paper research only when local cards miss and the case authorizes network access.
6. Copy a solver template into the case, record tool versions, and run it with a stated bound.
7. Prove the result, or mark the attempt rejected, blocked, or unsupported.

Never overwrite challenge inputs, install tools implicitly, or treat flag shape as
proof. Record public CTF constants only; keep tokens, cookies, real keys, and
private endpoints out of commands and case artifacts.

## References

- [Case workflow](references/workflow.md)
- [Proof requirements](references/validation.md)
