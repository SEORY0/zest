# Literature and adaptation gates

Use the local [AttackCard catalog](attack-cards.json) before external research.
This package stores citations and original summaries, not paper copies or third-party
challenge artifacts. Network access remains disabled unless the case manifest says
`network: allowed`; an authorization to read papers is not authorization to query a
challenge service.

## Source order

Prefer an author paper, DOI landing page, standards body, proceedings archive, or
immutable challenge repository. Use a secondary explanation only to find the primary
source. Record the exact DOI, ePrint number, repository SHA, source path, relevant
section or lines, and access date. Never pin a moving branch or a search-result URL.

## Six gates

All six gates must pass before a researched technique becomes an attempted solver.

1. **Source gate.** Record one canonical primary identifier and, for a wrapper-derived
   claim, an exact immutable `host/owner/repo@40-hex-sha/path:Lx-Ly` anchor. Repository
   URLs use canonical HTTPS without userinfo, query, fragment, encoded traversal, or
   ambiguous authority. A paper about a construction and source containing its name are
   not yet an attack.
2. **Family gate.** Map challenge variables, operations, variants, and aliases to one
   canonical family. Separate a paper's construction theorem from a later attack paper
   and from challenge-specific glue. If two families remain plausible, keep both as
   ranked hypotheses rather than merging them.
3. **Assumption gate.** List sufficient assumptions exactly, including bounds, sample
   count, independence, oracle access, group/domain checks, and alignment. Do not call
   a sufficient condition necessary. An inferred fact cannot satisfy this hard gate.
4. **Toy-instance gate.** Reproduce the same invariant on a faithful reduced instance
   with known secret values. A toy must preserve the relevant algebra and wrapper; a
   merely similar equation does not count.
5. **Round-trip gate.** Map paper inputs to challenge inputs and paper outputs back to
   a challenge-observable result. Verify an equation, signature, product, permutation,
   transcript, or encrypt/decrypt replay. A plausible key or printable plaintext is
   not a round trip.
6. **Negative gate.** Run the cheapest named false-friend checks and record why each
   alternative is rejected or still blocked. Do not erase failed hypotheses: keep the
   rule, evidence fact IDs, command, bound, and result in the case record.

## Claim boundaries

- `paper.matrix-product.trace-lattice` is a routing label. The matrix-product blueprint
  is ePrint 2023/1745; trace/determinant/characteristic-polynomial attacks are sourced
  to ePrint 2024/1332. Attribute only the exact theorem used.
- FROST ePrint 2020/852 specifies a threshold Schnorr construction and security proof.
  It is not evidence of a generic FROST exploit. Any weakness must be observed in the
  wrapper transcript or validation code.
- Bellare-Goldwasser-Micciancio's LCG result is for DSS. Generic ECDSA recurrence cards
  must write `k_i=(z_i+r_i*d)/s_i mod q`; pinned ECLCG additionally evolves integer
  states modulo a separate 311-bit `p`, so it requires the author solution's bounded
  mod-`p` to mod-`q` lifts and orthogonal/Stern bridge.
- UOV wrapper structure, CSIDH auxiliary-point leakage, adaptive subset-sum query
  schedules, GM ciphertext replication, and rotor permutation conjugacy are allowed
  only as challenge-derived observations at their pinned revisions. The unfairy-ring
  UOV route stays blocked until a concrete exploit invariant beyond honest verifier
  acceptance is established.
- A periodic round is not by itself a slide. For TokenCrypt, use the pinned 16-round
  chosen-pair service to recover the 16-bit Feistel subkey and 24x24 affine map, then
  invert all 64 chunks with `F^-1(state) XOR c`.

## Family references

- [RSA and number theory](families/rsa-and-number-theory.md)
- [Lattices and small roots](families/lattices-and-small-roots.md)
- [ECC and signatures](families/ecc-and-signatures.md)
- [PRNGs, streams, and oracles](families/prngs-streams-and-oracles.md)
- [Paper-derived constructions](families/paper-derived-constructions.md)

## Stop conditions

Stop and mark the attempt `rejected` when an exact assumption or toy invariant is
false. Mark it `blocked` when evidence, a required installed command, or the declared
budget is missing. Mark it `unsupported` when no precise local family remains and
network research is disabled. Never install a tool, widen an oracle authorization,
or copy a third-party artifact to turn a blocked card into an attempt.
