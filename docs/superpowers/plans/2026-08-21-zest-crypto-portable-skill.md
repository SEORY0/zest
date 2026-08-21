# Zest Crypto Portable Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a standalone `zest-crypto` Agent Skill that routes known crypto weaknesses quickly, extends to unfamiliar paper-derived constructions without hallucinating, and proves its decisions on difficult 2026 CTF benchmarks.

**Architecture:** Keep the skill offline-first. Small Python 3.8-compatible standard-library helpers parse conservative facts, validate a versioned AttackCard catalog, and rank only cards whose hard preconditions are satisfied. Markdown references carry mathematical guidance and source provenance; solver assets are copied into fresh case directories. Unknown constructions enter a paper-research fallback instead of a catch-all “try crypto” card.

**Tech Stack:** Markdown Agent Skill package, JSON catalog and fixtures, Python 3.8 standard library, SageMath-compatible `.sage` asset, Node 20+ `node:test`, existing Zest npm workspace and publisher.

**Spec:** `docs/superpowers/specs/2026-08-20-zest-crypto-portable-skill-design.md`

## Global Constraints

- The published skill remains standalone under `skills/zest-crypto/` and must not require companion skill files.
- Helper scripts use only the Python standard library, perform no network request, install no package, and start no persistent process.
- Python helpers run on the repository's observed Python 3.8.10 and include PEP 723 metadata with an empty dependency list.
- The default case constraint is `network: disabled`; online research requires an explicit `network: allowed` case record.
- Challenge inputs are never overwritten; all generated artifacts stay inside a fresh case directory.
- A candidate flag is never a solve without an exact equation, round trip, verifier, or transcript-replay proof.
- Hard preconditions and negative matches are evaluated before heuristic score.
- Inferred facts may rank signals but cannot satisfy hard preconditions or cause hard rejection.
- No full paper copies or third-party challenge artifacts are committed; store canonical citations, immutable source anchors, and local synthetic fixtures.
- Zest remains the byte-normalization tool. `zest-crypto` does not add mathematical solvers to `packages/core`.
- The source repository is authoritative; `npm run publish:skill -- --dry-run` validates the mirror without pushing.
- Current-year benchmarks are pinned to UofTCTF commit `8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac` and BSidesSF commit `68ee0e460eb572aaec17f082071f8ebf1d6f7330`.
- The implementation makes no universal-solvability claim. Its open-world contract is: solve supported families, research exact primary sources for unknown families when allowed, and report a precise blocked or unsupported state otherwise.

---

## File Structure

### Skill package

- Create `skills/zest-crypto/SKILL.md`: concise routing, core loop, authorization boundaries, and progressive-disclosure links.
- Create `skills/zest-crypto/references/workflow.md`: case layout, fingerprint lifecycle, probe/attempt/proof transitions, and output contract.
- Create `skills/zest-crypto/references/attack-card-schema.md`: fact vocabulary, predicate DSL, card/rank schemas, and extension rules.
- Create `skills/zest-crypto/references/literature.md`: offline-first paper retrieval and source/assumption/toy-instance gates.
- Create `skills/zest-crypto/references/validation.md`: proof types and rejection rules.
- Create `skills/zest-crypto/references/families/rsa-and-number-theory.md`: RSA cards and equations.
- Create `skills/zest-crypto/references/families/lattices-and-small-roots.md`: Coppersmith, HNP, subset-sum, and LLL parameter checks.
- Create `skills/zest-crypto/references/families/ecc-and-signatures.md`: ECDSA nonce and threshold-signature cards.
- Create `skills/zest-crypto/references/families/prngs-streams-and-oracles.md`: MT19937, LFSR, padding, and GM oracle cards.
- Create `skills/zest-crypto/references/families/paper-derived-constructions.md`: MatProd, FCA/LWPM, ECDSA-LCG, Wagner, FROST, UOV, CSIDH, slide, and rotor-family routing.
- Create `skills/zest-crypto/references/attack-cards.json`: 21 validated cards, including five current-year gap cards.

### Deterministic helpers

- Create `skills/zest-crypto/scripts/zest_crypto_types.py`: frozen domain values and typed boundary errors.
- Create `skills/zest-crypto/scripts/zest_crypto_parse.py`: JSON-to-domain parsing and schema checks.
- Create `skills/zest-crypto/scripts/zest_crypto_conditions.py`: three-valued predicate evaluation and deterministic ranking.
- Create `skills/zest-crypto/scripts/validate_attack_cards.py`: catalog validation CLI.
- Create `skills/zest-crypto/scripts/rank_attack_cards.py`: fingerprint/catalog ranking CLI.
- Create `skills/zest-crypto/scripts/fingerprint.py`: conservative source/artifact fingerprint CLI.

### Solver assets

- Create `skills/zest-crypto/assets/solver-templates/rsa_wiener.py`.
- Create `skills/zest-crypto/assets/solver-templates/rsa_common_modulus.py`.
- Create `skills/zest-crypto/assets/solver-templates/rsa_hastad.py`.
- Create `skills/zest-crypto/assets/solver-templates/coppersmith_univariate.sage`.
- Create `skills/zest-crypto/assets/solver-templates/ecdsa_nonce_reuse.py`.
- Create `skills/zest-crypto/assets/solver-templates/wagner_generalized_birthday.py`.
- Create `skills/zest-crypto/assets/solver-templates/lfsr_known_plaintext.py`.
- Create `skills/zest-crypto/assets/solver-templates/rotor_group_conjugacy.py`.

### Tests and evaluation

- Create `scripts/zest-crypto-package.test.mjs`: standalone footprint, links, catalog references, and prohibited-runtime checks.
- Create `scripts/zest-crypto-tools.test.mjs`: validator, ranker, fingerprint, tri-state, and deterministic-output tests.
- Create `scripts/zest-crypto-solvers.test.mjs`: executable solver-template fixtures.
- Create `scripts/fixtures/zest-crypto/catalog-invalid.json`: intentionally malformed catalog fixture.
- Create `scripts/fixtures/zest-crypto/fingerprints/*.json`: exact routing fixtures for supported and blocked paths.
- Create `scripts/fixtures/zest-crypto/sources/*.py`: small public synthetic source snippets for fingerprint extraction.
- Create `scripts/fixtures/zest-crypto/solvers/*.json`: solver inputs and expected public results.
- Create `docs/evals/2026-zest-crypto.md`: immutable benchmark sources, commands, outputs, timing, and observed limitations.

### Presentation

- Modify `README.md`: four-skill inventory, `zest-crypto` install command, scope, and verification evidence.
- Modify `packages/web/src/pages/SkillPage.tsx`: four-skill copy and `zest-crypto` install example.
- Modify `docs/superpowers/specs/2026-08-20-zest-crypto-portable-skill-design.md`: add the five 2026 gap cards, two solver assets, and current-year acceptance gate.

---

### Task 1: Lock the standalone package contract

**Files:**

- Create: `scripts/zest-crypto-package.test.mjs`
- Create: `skills/zest-crypto/SKILL.md`
- Create: `skills/zest-crypto/references/workflow.md`
- Create: `skills/zest-crypto/references/validation.md`
- Modify: `docs/superpowers/specs/2026-08-20-zest-crypto-portable-skill-design.md`

**Interfaces:**

- Consumes: the existing `node --test scripts/*.test.mjs` test surface and standalone-copy behavior in `scripts/publish-skill.mjs`.
- Produces: a valid skill entrypoint, explicit relative links, the case directory contract, and a machine-checkable package boundary used by all later tasks.

- [ ] **Step 1: Write the failing package tests**

Add Node tests that:

```js
const skillDirectory = join(root, 'skills', 'zest-crypto');
const entrypoint = join(skillDirectory, 'SKILL.md');
assert.equal(existsSync(entrypoint), true);
assert.equal(/^name:\s*zest-crypto$/m.test(await readFile(entrypoint, 'utf8')), true);
```

Walk every shipped `.md`, `.json`, `.py`, and `.sage` path. Resolve relative Markdown links inside `skillDirectory`; fail when a link escapes or targets a missing file. Assert there is no `README.md` inside the skill. Assert the entrypoint contains routing-bearing fragments for `paper-derived`, `math-heavy`, and `zest-ctf`, without pinning surrounding prose.

- [ ] **Step 2: Run the package test and confirm the red state**

Run: `node --test scripts/zest-crypto-package.test.mjs`

Expected: FAIL because `skills/zest-crypto/SKILL.md` does not exist.

- [ ] **Step 3: Add the concise entrypoint and core references**

`SKILL.md` must contain:

```yaml
---
name: zest-crypto
description: Analyze and solve math-heavy or paper-derived CTF cryptography involving RSA, ECC, lattices, signatures, PRNGs, stream ciphers, custom constructions, or crypto oracles. Use for attack selection, solver adaptation, and proof; route ordinary encoding-only blobs to zest-ctf.
---
```

The body must implement this short loop:

1. create a fresh case directory and hash inputs;
2. run `fingerprint.py` or record facts manually;
3. validate and rank local AttackCards;
4. probe the top eligible cards cheaply;
5. use primary-source paper research only when local cards miss and network is authorized;
6. copy a solver template into the case, record tool versions, and run with a bound;
7. prove the result or mark the attempt rejected/blocked.

`workflow.md` defines `case/{manifest.json,inputs,notes,solvers,transcripts,proof}` and the states `fingerprinted`, `ranked`, `probed`, `attempted`, `verified`, `rejected`, `blocked`, and `unsupported`.

`validation.md` defines equation, round-trip, verifier, transcript-replay, and exact-file-digest proof. It explicitly states that flag shape and printability are supporting evidence only.

- [ ] **Step 4: Extend the design spec with the 2026 addendum**

Add these card IDs to the exact inventory and change the target count from 16 to 21:

```text
lattice.subset-sum.query-schedule
stream.lfsr.known-plaintext
symmetric.slide.periodic-round
oracle.goldwasser-micali.replication
symmetric.rotor.group-conjugacy
```

Add `lfsr_known_plaintext.py` and `rotor_group_conjugacy.py` to the solver layout. Add a current-year gate requiring exact top-three routing for all five pinned 2026 cases and end-to-end proof for `lfstream` plus `Rotor Cipher`.

- [ ] **Step 5: Run the package test and commit**

Run: `node --test scripts/zest-crypto-package.test.mjs`

Expected: PASS for the entrypoint and currently present references; the test must tolerate resources introduced by later tasks while still rejecting broken links.

Commit:

```bash
git add scripts/zest-crypto-package.test.mjs skills/zest-crypto docs/superpowers/specs/2026-08-20-zest-crypto-portable-skill-design.md
git commit -m "Define the Zest crypto skill contract"
```

### Task 2: Parse and validate fingerprints and AttackCards

**Files:**

- Create: `skills/zest-crypto/scripts/zest_crypto_types.py`
- Create: `skills/zest-crypto/scripts/zest_crypto_parse.py`
- Create: `skills/zest-crypto/scripts/validate_attack_cards.py`
- Create: `skills/zest-crypto/references/attack-card-schema.md`
- Create: `scripts/zest-crypto-tools.test.mjs`
- Create: `scripts/fixtures/zest-crypto/catalog-invalid.json`
- Create: `scripts/fixtures/zest-crypto/fingerprints/rsa-hastad.json`

**Interfaces:**

- Consumes: fingerprint and AttackCard shapes from the spec.
- Produces:
  - `parse_fingerprint(raw: JsonValue) -> Fingerprint`
  - `parse_catalog(raw: JsonValue) -> tuple[AttackCard, ...]`
  - `validate_catalog(cards: tuple[AttackCard, ...], skill_root: Path) -> tuple[CatalogIssue, ...]`
  - CLI: `python3 validate_attack_cards.py ATTACK_CARDS_JSON`, exit `0` with a JSON summary or exit `2` with structured issues.

- [ ] **Step 1: Write red validator tests**

Spawn the CLI with `node:child_process.execFile`. Given the malformed fixture, assert exit code `2` and parse stdout as:

```json
{
  "ok": false,
  "issues": [
    {"path": "$[0].id", "code": "invalid-card-id"}
  ]
}
```

Given the real catalog path before it exists, assert failure for the missing input boundary.

- [ ] **Step 2: Run the focused test and confirm the red state**

Run: `node --test --test-name-pattern='validator' scripts/zest-crypto-tools.test.mjs`

Expected: FAIL because the CLI and catalog do not exist.

- [ ] **Step 3: Implement frozen domain types and typed errors**

Use `@dataclass(frozen=True)` on Python 3.8, because `slots=True` is unavailable until Python 3.10. Define `FactStatus`, `Truth`, `CardState`, and `CostClass` as enums. Define branded `NewType` values for `FactKey`, `FactId`, and `CardId`.

The public models are:

```python
@dataclass(frozen=True)
class Fact:
    id: FactId
    key: FactKey
    value: FactValue
    status: FactStatus
    evidence: Evidence

@dataclass(frozen=True)
class Fingerprint:
    schema_version: int
    case_id: str
    inputs: tuple[InputArtifact, ...]
    facts: tuple[Fact, ...]
    capabilities: tuple[Capability, ...]
    constraints: Constraints

@dataclass(frozen=True)
class AttackCard:
    id: CardId
    version: int
    canonical_family_id: str
    signals: tuple[Signal, ...]
    requires: tuple[Rule, ...]
    rejects: tuple[Rule, ...]
    negative_matches: tuple[NegativeMatch, ...]
    expected_cost: Cost
    tooling: tuple[ToolRequirement, ...]
    template: str | None
```

In source, use `typing.Optional` only where Python 3.8 parsing requires it; keep that compatibility exception confined to the type module. Boundary failures use a frozen `ParseError(Exception)` with `path`, `code`, and `detail`, plus an explicit `__str__`.

- [ ] **Step 4: Implement boundary parsing and validation**

`zest_crypto_parse.py` parses raw JSON exactly once. It rejects unknown schema versions, duplicate fact/card IDs, unknown fact keys, unknown operators, boolean nesting deeper than two, out-of-range signal weights, invalid relative template paths, missing citation identifiers, and research-tier cards without pinned examples.

The CLI reads with `Path.read_text(encoding='utf-8')`, catches only `OSError`, `json.JSONDecodeError`, and `ParseError`, and emits stable JSON to stdout. It never imports network or package-management modules.

- [ ] **Step 5: Document the exact schema and make tests green**

`attack-card-schema.md` must list every fact key, value type, operator, tri-state rule, cost penalty, and output field. It must show one complete card and one complete rank report that parse successfully.

Run:

```bash
node --test --test-name-pattern='validator' scripts/zest-crypto-tools.test.mjs
python3 -m py_compile skills/zest-crypto/scripts/*.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add skills/zest-crypto/scripts skills/zest-crypto/references/attack-card-schema.md scripts/zest-crypto-tools.test.mjs scripts/fixtures/zest-crypto
git commit -m "Validate Zest crypto attack cards"
```

### Task 3: Implement deterministic condition evaluation and ranking

**Files:**

- Create: `skills/zest-crypto/scripts/zest_crypto_conditions.py`
- Create: `skills/zest-crypto/scripts/rank_attack_cards.py`
- Modify: `scripts/zest-crypto-tools.test.mjs`
- Create: `scripts/fixtures/zest-crypto/fingerprints/blocked-sage.json`
- Create: `scripts/fixtures/zest-crypto/fingerprints/inferred-family.json`

**Interfaces:**

- Consumes: parsed `Fingerprint` and `AttackCard` values.
- Produces:
  - `evaluate_condition(condition: Condition, facts: FactIndex, hard: bool) -> Truth`
  - `classify_card(card: AttackCard, facts: FactIndex) -> CardEvaluation`
  - `rank_cards(fingerprint: Fingerprint, cards: tuple[AttackCard, ...]) -> RankReport`
  - CLI: `python3 rank_attack_cards.py FINGERPRINT_JSON ATTACK_CARDS_JSON`.

- [ ] **Step 1: Add red ranking tests**

Cover one behavior per test:

- all hard requirements true yields `eligible`;
- a false requirement yields `rejected`;
- a missing requirement yields `blocked`;
- an inferred fact yields `unknown` for requires, rejects, and negative matches;
- an inferred fact can contribute signal weight;
- `negative_matches.unknown_policy=block` yields `blocked`;
- score equals signal sum minus exactly one cost penalty;
- ties sort by ascending `card_id`;
- identical inputs produce byte-identical JSON and identical catalog/fingerprint digests;
- a missing required command appears as a blocked tool reason without executing an installer.

- [ ] **Step 2: Run and observe the red state**

Run: `node --test --test-name-pattern='rank|condition|deterministic' scripts/zest-crypto-tools.test.mjs`

Expected: FAIL because ranking functions are absent.

- [ ] **Step 3: Implement the predicate dispatch table**

Implement exact operators `exists`, `eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `in`, `contains`, `len_eq`, and `len_gte`. Use a mapping from operator enum to a small predicate function; do not implement a variant `if/elif` chain.

Apply states in this order:

```text
matched reject -> rejected
matched negative -> rejected
false require -> rejected
unknown blocking negative -> blocked
unknown require -> blocked
missing required command -> blocked
otherwise -> eligible
```

Only eligible cards enter `eligible`; blocked and rejected cards remain in separate arrays with rule IDs and evidence fact IDs.

- [ ] **Step 4: Implement canonical JSON ranking output**

Use `json.dumps(..., sort_keys=True, separators=(',', ':'))` for digests and `json.dumps(..., sort_keys=True, indent=2)` for CLI output. Sort card arrays by state-specific rank, descending score, then card ID.

- [ ] **Step 5: Run tests and commit**

Run:

```bash
node --test scripts/zest-crypto-tools.test.mjs
python3 -m py_compile skills/zest-crypto/scripts/*.py
```

Expected: PASS.

Commit:

```bash
git add skills/zest-crypto/scripts scripts/zest-crypto-tools.test.mjs scripts/fixtures/zest-crypto/fingerprints
git commit -m "Rank Zest crypto attack hypotheses"
```

### Task 4: Build conservative source fingerprinting

**Files:**

- Create: `skills/zest-crypto/scripts/fingerprint.py`
- Modify: `scripts/zest-crypto-tools.test.mjs`
- Create: `scripts/fixtures/zest-crypto/sources/rsa_broadcast.py`
- Create: `scripts/fixtures/zest-crypto/sources/ecdsa_reuse.py`
- Create: `scripts/fixtures/zest-crypto/sources/paper_family.py`

**Interfaces:**

- Consumes: one or more local source/artifact paths and optional case ID.
- Produces: fingerprint schema version 1 on stdout. Direct observations include input SHA-256 and source locator; derived facts cite source fact IDs; uncertain family clues are `inferred`.
- CLI: `python3 fingerprint.py CASE_ID PATH [PATH ...]`.

- [ ] **Step 1: Add red fingerprint tests**

Given the small source fixtures, assert machine facts rather than prose:

- RSA fixture emits `rsa.public_exponent`, `rsa.moduli`, `rsa.ciphertexts`, and `rsa.same_plaintext` only when alignment is explicit.
- ECDSA fixture emits `signature.scheme`, `signature.sample_count`, and `signature.repeated_r` from literal samples.
- Paper fixture emits `construction.paper_ids` and an inferred canonical family clue.
- All inputs contain exact SHA-256 digests.
- No input file changes after the command.
- No fact is fabricated for a dynamic expression such as `n = get_modulus()`.

- [ ] **Step 2: Run and confirm red**

Run: `node --test --test-name-pattern='fingerprint' scripts/zest-crypto-tools.test.mjs`

Expected: FAIL because `fingerprint.py` is absent.

- [ ] **Step 3: Implement extraction**

Use Python's `ast` module for literal assignments and call names. Use regex only for canonical DOI/ePrint URLs, hexadecimal integers in transcript text, and exact clue tokens. Record clues for `small_roots`, `LLL`, `EllipticCurve`, repeated signature tuples, `MT19937`, `LFSR`, `Goldwasser`, `FROST`, `UOV`, `CSIDH`, and repeated-round/slide structures.

Tool capabilities are discovered only with `shutil.which`. Do not execute tools during fingerprinting; version capture belongs to the case workflow immediately before solver execution.

- [ ] **Step 4: Run tests and commit**

Run:

```bash
node --test scripts/zest-crypto-tools.test.mjs
python3 -m py_compile skills/zest-crypto/scripts/*.py
```

Expected: PASS.

Commit:

```bash
git add skills/zest-crypto/scripts/fingerprint.py scripts/zest-crypto-tools.test.mjs scripts/fixtures/zest-crypto/sources
git commit -m "Fingerprint crypto challenge sources"
```

### Task 5: Populate 21 precise AttackCards and references

**Files:**

- Create: `skills/zest-crypto/references/attack-cards.json`
- Create: `skills/zest-crypto/references/literature.md`
- Create: `skills/zest-crypto/references/families/rsa-and-number-theory.md`
- Create: `skills/zest-crypto/references/families/lattices-and-small-roots.md`
- Create: `skills/zest-crypto/references/families/ecc-and-signatures.md`
- Create: `skills/zest-crypto/references/families/prngs-streams-and-oracles.md`
- Create: `skills/zest-crypto/references/families/paper-derived-constructions.md`
- Modify: `scripts/zest-crypto-package.test.mjs`
- Modify: `scripts/zest-crypto-tools.test.mjs`

**Interfaces:**

- Consumes: exact schema and ranker.
- Produces: the local decision catalog and human mathematical explanations.

- [ ] **Step 1: Add red catalog coverage tests**

Parse the real catalog and assert the exact set of IDs:

```text
rsa.wiener.small-d
rsa.common-modulus.coprime-exponents
rsa.hastad.broadcast
rsa.franklin-reiter.related-message
lattice.coppersmith.univariate-small-root
signature.ecdsa.reused-nonce
signature.ecdsa.partial-nonce-hnp
prng.mt19937.state-clone
oracle.cbc-padding
paper.matrix-product.trace-lattice
paper.stream-cipher.fca-lwpm
paper.ecdsa.lcg-nonce
paper.wagner.generalized-birthday
paper.frost.threshold-signature
paper.uov.wrapper-structure
paper.csidh.auxiliary-point-leak
lattice.subset-sum.query-schedule
stream.lfsr.known-plaintext
symmetric.slide.periodic-round
oracle.goldwasser-micali.replication
symmetric.rotor.group-conjugacy
```

Assert every card has at least one requirement, one cheap probe, one verification step, one canonical citation, and either a bundled template or an explicit `template: null` plus a solver outline.

- [ ] **Step 2: Run and confirm red**

Run: `node --test --test-name-pattern='catalog' scripts/zest-crypto-tools.test.mjs`

Expected: FAIL because the catalog does not exist.

- [ ] **Step 3: Write baseline cards**

For each baseline card, encode exact fact predicates, rejection conditions, cost, required commands, procedure, and proof. Cite primary papers or authoritative standards; do not cite generic blog tutorials when a primary source exists.

- [ ] **Step 4: Write paper-derived and 2026 cards**

Pin challenge examples to immutable source paths:

```text
UofTCTF/uoftctf-2026-chals-public@8519e2bb.../mat347/dist/chall.py
UofTCTF/uoftctf-2026-chals-public@8519e2bb.../rotor-cipher/rotor_cipher.py
BSidesSF/ctf-2026-release@68ee0e46.../lfstream/challenge/lfsr_crypt.py
BSidesSF/ctf-2026-release@68ee0e46.../tokencrypt/distfiles/tokencrypt.py
BSidesSF/ctf-2026-release@68ee0e46.../kproof/challenge/src/kproof.go
```

`MAT347` must prefer `lattice.subset-sum.query-schedule` and explicitly mark naive Wagner routing as a negative match. `Rotor Cipher` maps to group conjugacy of observed permutations. `lfstream` maps known PNG plaintext to Galois-LFSR tap recovery. `tokencrypt` maps a periodic round function to a slide attack. `kproof` maps repeated GM ciphertext bits to an all-zero/all-one AES-key oracle.

- [ ] **Step 5: Write progressive-disclosure family references**

Each card section contains: observable signals, equations, hard assumptions, cheapest falsifier, expected cost, solver adaptation notes, failure interpretation, proof, primary citation, and pinned challenge example. `literature.md` defines source, family, assumption, toy-instance, round-trip, and negative gates.

- [ ] **Step 6: Validate, rank fixtures, and commit**

Run:

```bash
python3 skills/zest-crypto/scripts/validate_attack_cards.py skills/zest-crypto/references/attack-cards.json
node --test scripts/zest-crypto-package.test.mjs scripts/zest-crypto-tools.test.mjs
```

Expected: 21 valid cards; PASS.

Commit:

```bash
git add skills/zest-crypto/references scripts/zest-crypto-package.test.mjs scripts/zest-crypto-tools.test.mjs
git commit -m "Add the Zest crypto attack catalog"
```

### Task 6: Add executable solver templates

**Files:**

- Create: eight files under `skills/zest-crypto/assets/solver-templates/`
- Create: `scripts/zest-crypto-solvers.test.mjs`
- Create: public solver fixtures under `scripts/fixtures/zest-crypto/solvers/`

**Interfaces:**

- Consumes: a JSON fixture path for pure-Python number-theory templates; explicit files/arguments for LFSR and rotor templates; Sage JSON input for Coppersmith.
- Produces: JSON on stdout containing recovered public values and a `verified` boolean. Exit `0` only when the template's exact proof succeeds.

- [ ] **Step 1: Write red solver tests**

Add independent fixtures and expected results for:

- Wiener: recovered `d`, exact factors, decrypt/re-encrypt proof;
- common modulus: recovered message, both ciphertext equations;
- Håstad: exact integer root and all ciphertext equations;
- ECDSA nonce reuse: recovered `k` and private scalar, both signature equations;
- Wagner: a small four-list exact-sum instance;
- LFSR: encrypted synthetic PNG prefix and exact plaintext digest;
- rotor group conjugacy: reduced six-symbol rotor instance and exact recovered permutation;
- Coppersmith: static structural validation when Sage is absent; execute a tiny root fixture when `sage` exists.

- [ ] **Step 2: Run and confirm red**

Run: `node --test scripts/zest-crypto-solvers.test.mjs`

Expected: FAIL because templates are absent.

- [ ] **Step 3: Implement the pure-Python templates**

Each template is self-contained, has empty PEP 723 dependencies, accepts only public challenge values, uses bounded loops, emits a proof-bearing JSON object, and has no network/import/install behavior. Integer-root code must check `root ** e == value`; modular inverses must verify the congruence; rotor and LFSR candidates must reproduce every supplied observation.

- [ ] **Step 4: Add the Sage template**

`coppersmith_univariate.sage` reads `modulus`, coefficient list, and bound from JSON, constructs a monic polynomial over `Zmod(n)`, runs `small_roots(X=bound, beta=...)`, and verifies every returned root in the original congruence. When Sage is absent, the Node test records a skip rather than installing it.

- [ ] **Step 5: Run tests and commit**

Run:

```bash
node --test scripts/zest-crypto-solvers.test.mjs
python3 -m py_compile skills/zest-crypto/assets/solver-templates/*.py
```

Expected: all available-runtime cases PASS; Sage is explicitly skipped if absent.

Commit:

```bash
git add skills/zest-crypto/assets scripts/zest-crypto-solvers.test.mjs scripts/fixtures/zest-crypto/solvers
git commit -m "Add reusable crypto solver templates"
```

### Task 7: Present and package the fourth skill

**Files:**

- Modify: `README.md`
- Modify: `packages/web/src/pages/SkillPage.tsx`
- Modify: `scripts/zest-crypto-package.test.mjs`

**Interfaces:**

- Consumes: the complete skill package and existing website design system.
- Produces: accurate four-skill installation and scope copy without a new route or visual component.

- [ ] **Step 1: Add red presentation/package assertions**

Assert the generated standalone README from a publication dry-run contains `--skill zest-crypto` through parsed skill enumeration. For the web copy, rely on TypeScript build and manual rendering; do not pin prose in a unit test.

- [ ] **Step 2: Update repository and website copy**

Change “three skills” to “four skills”, add `skills/zest-crypto` to the layout table, add the one-skill install command, and describe the boundary between `zest-ctf` byte puzzles and `zest-crypto` mathematical/paper-derived work. Preserve the existing components and responsive CSS.

- [ ] **Step 3: Build and run publication dry-run**

Run:

```bash
npm run build:web
npm run publish:skill -- --dry-run
```

Expected: web build exits `0`; dry run lists all `zest-crypto` resources and performs no push.

- [ ] **Step 4: Manually render the Skill page**

Run the production web build or preview, open the Skill page at 375px and 1280px, and confirm the fourth skill, install command, copy button, navigation, and tables remain visible without document-level horizontal overflow.

- [ ] **Step 5: Commit**

```bash
git add README.md packages/web/src/pages/SkillPage.tsx scripts/zest-crypto-package.test.mjs
git commit -m "Present the Zest crypto skill"
```

### Task 8: Evaluate difficult 2026 CTF challenges

**Files:**

- Create: `docs/evals/2026-zest-crypto.md`
- Create: five benchmark fingerprint fixtures under `scripts/fixtures/zest-crypto/fingerprints/2026/`
- Modify: `scripts/zest-crypto-tools.test.mjs`

**Interfaces:**

- Consumes: pinned public source repositories, fingerprint CLI, ranker, solver assets, and independent solving agents.
- Produces: exact top-three routing assertions, two end-to-end proofs, three honest routing/tool-bound reports, elapsed times, and immutable provenance.

- [ ] **Step 1: Clone pinned sources into a fresh temporary directory**

Run:

```bash
case_dir="$(mktemp -d /tmp/zest-crypto-2026.XXXXXX)"
git clone --quiet https://github.com/UofTCTF/uoftctf-2026-chals-public.git "$case_dir/uoft"
git -C "$case_dir/uoft" checkout --quiet 8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac
git clone --quiet https://github.com/BSidesSF/ctf-2026-release.git "$case_dir/bsidessf"
git -C "$case_dir/bsidessf" checkout --quiet 68ee0e460eb572aaec17f082071f8ebf1d6f7330
```

Do not copy official solution directories into the blind evaluation workspace.

- [ ] **Step 2: Generate and lock routing fixtures**

Fingerprint the five challenge source paths named in Task 5. Add only normalized public facts, repository SHA, source path, and expected card ID to repository fixtures. Do not commit challenge files, flags, live endpoints, or official solver code.

Add tests requiring the exact intended card in top three for all five and top one for at least four.

- [ ] **Step 3: Run independent blind routing evaluation**

Give independent agents only the skill, challenge description/source without `solve/`, and a fresh case directory. Record their chosen cards, evidence, rejected alternatives, tool availability, and time to justified hypothesis.

Expected mappings:

```text
MAT347 -> lattice.subset-sum.query-schedule
Rotor Cipher -> symmetric.rotor.group-conjugacy
lfstream -> stream.lfsr.known-plaintext
tokencrypt -> symmetric.slide.periodic-round
kproof -> oracle.goldwasser-micali.replication
```

- [ ] **Step 4: Run end-to-end `lfstream` proof**

Use the challenge ciphertext and known PNG header with the bundled LFSR template. Verify the recovered file digest equals the repository's challenge-side plaintext image digest and that the original encrypted artifact digest is unchanged.

- [ ] **Step 5: Run end-to-end `Rotor Cipher` proof**

Use `rotor_cipher.log` and the distributed cipher implementation, excluding the official solver. Recover rotor/reflector permutations, run them through the challenge verifier or local implementation, and verify the exact static flag from `challenge.yml`.

- [ ] **Step 6: Exercise hard blocked paths**

For `MAT347`, verify that the agent identifies the lattice/query-schedule route and reports SageMath as missing without attempting installation. For `tokencrypt` and `kproof`, verify exact family routing and explain which local transcript/service evidence is required before an end-to-end attempt.

- [ ] **Step 7: Write the evidence report and commit**

`docs/evals/2026-zest-crypto.md` records event, date, solve count or 1000-point metadata, immutable SHA/path, commands, elapsed time, top-three order, proof artifact digest, result, and limitations. It distinguishes our execution from official solver confirmation.

Commit:

```bash
git add docs/evals/2026-zest-crypto.md scripts/fixtures/zest-crypto/fingerprints/2026 scripts/zest-crypto-tools.test.mjs
git commit -m "Evaluate Zest crypto on 2026 CTFs"
```

### Task 9: Full validation and release-ready handoff

**Files:**

- Modify only files required by observed failures.

**Interfaces:**

- Consumes: all implementation and evaluation commits.
- Produces: green repository checks, a valid standalone skill, clean worktree, and exact local commit history. No push occurs in this task.

- [ ] **Step 1: Run skill validation**

Run:

```bash
python3 /home/seory0/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/zest-crypto
python3 skills/zest-crypto/scripts/validate_attack_cards.py skills/zest-crypto/references/attack-cards.json
python3 -m py_compile skills/zest-crypto/scripts/*.py skills/zest-crypto/assets/solver-templates/*.py
```

- [ ] **Step 2: Run targeted and full repository checks**

Run:

```bash
node --test scripts/zest-crypto-package.test.mjs scripts/zest-crypto-tools.test.mjs scripts/zest-crypto-solvers.test.mjs
npm test
npm run build
npm run build:web
npm run publish:skill -- --dry-run
git diff --check
```

- [ ] **Step 3: Run the no-network/no-install audit**

Search shipped helpers and assets for `socket`, `urllib`, `http`, `requests`, `subprocess` installer invocations, `pip`, `apt`, `brew`, `npm install`, daemon loops, and writes outside an explicit case/output path. Inspect every match; comments that describe prohibited actions are allowed, executable paths are not.

- [ ] **Step 4: Run the code-size and architecture review**

Measure every changed `.py`, `.mjs`, `.ts`, and `.tsx` file. Split source modules above 250 pure LOC unless the file is the pure-data `attack-cards.json` or an immutable test fixture. Confirm single responsibility, parsed boundaries, no untyped public dictionaries, no silent broad catches, no parameter mutation, and a regression test for each behavior.

- [ ] **Step 5: Request independent code and skill review**

Reviewers inspect correctness, security boundaries, catalog citations, portability, standalone packaging, test adequacy, and 2026 evaluation claims. Fix every blocking finding and rerun only affected checks followed by the full final check once.

- [ ] **Step 6: Commit final repairs and report state**

Use the repository's imperative commit style. Report all commit hashes, test totals, skipped Sage coverage, 2026 outcomes, remaining unsupported families, and whether the branch is ahead of origin. Do not push unless separately requested.

---

## Execution Choice

The user explicitly requested implementation and testing in this session. Use **Subagent-Driven Development**: dispatch bounded ownership for catalog/references, solver templates, and current-year QA; the leader owns shared schemas, integration, review, and final verification.
