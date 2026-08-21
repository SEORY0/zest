# AttackCard and fingerprint schema

The catalog and fingerprint formats are versioned JSON boundaries. Versions
`1` and `2` are accepted; version `2` is current and is emitted by new
fingerprints and the shipped catalog. Version `1` is deprecated and read-only:
its structural shape and original 36 fact keys remain readable only when every
provenance value also satisfies the current canonical URL, source-range, and
source-anchor safety rules. This is an intentional security tightening. Query,
userinfo, and raw-space URLs, free-form source ranges, and arbitrary source
anchors accepted by the historical v1 implementation are rejected with stable
validation codes. New or migrated documents should use v2.

The parser never falls back from v1 to v2 and never repairs an unsafe value.
For an accepted canonical v1 catalog, typed parsing followed by the version-
aware catalog serializer preserves decoded card values and the v1 structural
shape, including omission of `source_kind`. Preservation of original whitespace
or object-key order is not promised. Typed fingerprint serialization may
materialize documented constraint defaults, so no raw fingerprint round trip is
promised. Rank-report digests are stable SHA-256 hashes of each exact decoded
input document under sorted compact JSON encoding; they are never digests of a
typed reserialization. Rejected historical inputs produce neither a round trip
nor a rank digest. Decode JSON once at the command boundary, then pass the
resulting JSON value to `parse_fingerprint` or `parse_catalog`; never place
serialized JSON inside a fact or card field. Any other version fails with
`unknown-schema-version`.

`validate_attack_cards.py ATTACK_CARDS_JSON` writes one JSON object to standard
output. It exits `0` for a valid catalog:

```json
{
  "card_count": 1,
  "issues": [],
  "ok": true
}
```

It exits `2` for an input, JSON, parse, or cross-card validation failure. Every
issue has a JSONPath-like `path` and stable `code`; host-specific error details
are intentionally not emitted.

```json
{
  "issues": [
    {
      "code": "invalid-card-id",
      "path": "$[0].id"
    }
  ],
  "ok": false
}
```

## Fingerprints

A fingerprint object has exactly these top-level fields:

```text
schema_version: integer  (must be 1 or 2)
case_id: string
inputs: InputArtifact[]
facts: Fact[]
capabilities: Capability[]
constraints: Constraints
```

An `InputArtifact` has `id`, a normalized case-relative `path`, 64 lowercase
hexadecimal `sha256`, and `media_type`. `Capability` has `command`, `available`,
and `version` (a string or `null`). `constraints.network` is `disabled` or
`allowed` and defaults to `disabled`; `max_seconds`, `max_memory_mb`, and
`max_oracle_queries` are non-negative integers when present. During ranking, the
effective `oracle.query_budget` is the lower of its observed fact value and
`constraints.max_oracle_queries` when both exist.

Each fact has `id`, `key`, `value`, `value_type`, `status`, and `evidence`.
The allowed value types are `boolean`, `integer`, `number`, `string`,
`integer_list`, and `string_list`. A Boolean is not an integer. List values
become immutable tuples after parsing. A `number` must be finite: `NaN`,
`Infinity`, and a JSON decimal that overflows to infinity are invalid.

`status` is `observed`, `derived`, or `inferred`.

- Observed evidence requires `input_id` and `locator`.
- Derived evidence requires non-empty `source_fact_ids` naming existing facts
  and a non-empty `rationale` describing the derivation. A derived fact cannot
  cite itself, and the derived-fact source graph cannot contain a cycle.
- Inferred evidence requires a non-empty `rationale`.

The finite v1 fact vocabulary is:

| Fact key | Value type |
| --- | --- |
| `rsa.modulus` | `integer` |
| `rsa.moduli` | `integer_list` |
| `rsa.public_exponent` | `integer` |
| `rsa.public_exponents` | `integer_list` |
| `rsa.ciphertexts` | `integer_list` |
| `rsa.same_plaintext` | `boolean` |
| `rsa.message_relation_type` | `string` |
| `rsa.moduli_pairwise_coprime` | `boolean` |
| `rsa.exponents_coprime` | `boolean` |
| `rsa.public_exponent_ratio` | `number` |
| `rsa.factorization_verified` | `boolean` |
| `rsa.private_exponent` | `integer` |
| `lattice.polynomial` | `string` |
| `lattice.modulus` | `integer` |
| `lattice.unknown_bound` | `integer` |
| `signature.scheme` | `string` |
| `signature.sample_count` | `integer` |
| `signature.public_key_present` | `boolean` |
| `signature.repeated_r` | `boolean` |
| `signature.nonce_leak_bits` | `integer` |
| `signature.nonce_bias_bound` | `integer` |
| `signature.nonce_recurrence` | `string` |
| `prng.family` | `string` |
| `prng.output_count` | `integer` |
| `prng.output_word_bits` | `integer` |
| `prng.outputs_aligned` | `boolean` |
| `oracle.kind` | `string` |
| `oracle.distinguishable_response` | `boolean` |
| `oracle.chosen_ciphertext` | `boolean` |
| `oracle.query_budget` | `integer` |
| `construction.canonical_family` | `string` |
| `construction.paper_ids` | `string_list` |
| `construction.source_anchors` | `string_list` |
| `construction.parameter_signature` | `string_list` |
| `construction.toy_invariant_verified` | `boolean` |
| `construction.negative_matches_checked` | `string_list` |

Version 2 retains every v1 key and adds exactly these six keys:

| Fact key | Value type |
| --- | --- |
| `signature.nonce_leak_orientation` | `string` |
| `signature.hnp_model` | `string` |
| `signature.hnp_parameter_bound_verified` | `boolean` |
| `signature.nonce_projection_bound_verified` | `boolean` |
| `oracle.recovery_bytes` | `integer` |
| `construction.exploit_invariant_verified` | `boolean` |

Unknown keys and a mismatched `value_type` are rejected. Fact IDs and fact keys
must each be unique within a fingerprint; card IDs must be unique within the
catalog. `FactIndex` maps each fact key to one fact, so a duplicate key is
rejected instead of silently selecting an order-dependent value or evidence
record.

In both schema versions, every `construction.source_anchors` element uses the canonical form
`host/owner/repo@40-lowercase-hex-sha/path:Lx-Ly`. The host is lowercase, source
paths are normalized and percent-encode spaces canonically, line numbers are
positive without leading zeroes, and traversal or encoded slash/backslash
ambiguities are rejected even for fingerprints parsed directly from JSON.

## Predicate DSL and tri-state semantics

A condition is either a predicate or one Boolean group. A predicate has
`fact`, `op`, and, except for `exists`, `value`. A group has exactly one of
`all`, `any`, or `not`. Boolean groups may nest to two levels; a third group is
invalid. Values are checked against the fact vocabulary at catalog-validation
time.

| Operator | Accepted fact types | Value and meaning |
| --- | --- | --- |
| `exists` | all | no value; the fact is present |
| `eq` / `neq` | all | one value of the exact declared fact type |
| `lt` / `lte` / `gt` / `gte` | `integer`, `number` | one finite numeric value of the declared type |
| `in` | all | non-empty typed candidate array; for a scalar fact, the scalar is in that array; for a list fact, at least one fact element is in that array |
| `contains` | `string`, `integer_list`, `string_list` | a string substring or one correctly typed list element |
| `len_eq` / `len_gte` | `string`, `integer_list`, `string_list` | one non-negative integer length |

Evaluation returns `true`, `false`, or `unknown`. A missing fact is `unknown`,
except `exists`, which is `false`. An inferred fact can contribute a signal but
is `unknown` for `requires`, `rejects`, and `negative_matches`. A type mismatch
is a validation error, never `false`.

Cards are processed before scoring: a true rejection or negative match rejects;
a false requirement rejects; an unknown blocking negative match or unknown
requirement blocks; otherwise the card is eligible. `negative_matches` includes
`id`, `when`, `reason`, and `unknown_policy`, which is either `ignore` or
`block`.

## AttackCards

The catalog is an array of full card objects. Every card has these fields:

```text
schema_version, id, version, title, canonical_family_id, family_aliases,
summary, parameter_signature, signals, requires, rejects, negative_matches,
cheap_probes, expected_cost, tooling, template, procedure, citations, examples,
verification
```

`id` contains lowercase segments separated by dots or hyphens, such as
`rsa.hastad.broadcast`. `parameter_signature` and each cheap probe's
`produces_facts` use fact keys from the table above. Signals have `id`, `when`,
integer `weight` in `[-100, 100]`, and `reason`. Requirements and rejections
have `id`, `when`, and `reason`.

`expected_cost.class` is `low`, `medium`, `high`, or `oracle-bound`; the fixed
ranking penalty is respectively `0`, `10`, `25`, or `15`, subtracted exactly
once after matched signal weights are summed. It also has non-empty `notes`.

`tooling` entries have `command`, Boolean `required`, string-array `packages`,
and `reason`. `template` is `null` or a normalized package-relative path. It
cannot be absolute, contain a NUL, use a parent component, alternate separator,
or redundant component, or otherwise escape the skill root. The parser
validates containment but does not test file presence: packaged template
existence is a separate package-integrity check.

Each citation has `kind`, non-empty `paper_id`, `title`, canonical HTTPS `url`,
positive `year`, `section`, non-empty string-array `assumptions`, and
`verified_on`. Canonical HTTPS strings have no leading or trailing whitespace
and begin with the exact lowercase bytes `https://` before URL parsing.

The deprecated, read-only v1 pinned-example object has `challenge_id`, `event`, positive `year`,
canonical HTTPS `repo_url`, a 40-lowercase-hex `repo_sha`, normalized relative
`source_path`, one inclusive `source_lines` span in canonical `Lx-Ly` form, and
`inference_level` (`direct` or `inferred`). It is remote-only and does not have
`source_kind`. Parsing v1 creates a typed example with `source_kind=remote`,
while version-aware serialization restores the accepted v1 structural shape
and declared version. It does not canonicalize or otherwise rewrite values.

Version 2 adds mandatory `source_kind` and the `variant` inference level. A
`remote` v2 example requires the same canonical repository URL and commit SHA.
A `local` v2 example requires both repository fields to be `null` and its
source path to remain inside the skill package. V2-only fields or values are
invalid under v1, and the source-kind-less v1 shape is invalid under v2. Cards
with IDs starting `paper.` are research tier and require at least one pinned
example.
`cheap_probes` have `id`, `instruction`, non-negative `max_seconds`, and
`produces_facts`; procedure entries have `id` and `instruction`; verification
entries have `kind` and `instruction`.

The following complete card is valid JSON and parses with `parse_catalog`:

```json
[
  {
    "schema_version": 2,
    "id": "rsa.hastad.broadcast",
    "version": 1,
    "title": "Hastad broadcast example",
    "canonical_family_id": "rsa.low-public-exponent",
    "family_aliases": ["broadcast RSA"],
    "summary": "Combine same-message ciphertexts under coprime moduli.",
    "parameter_signature": [
      "rsa.moduli",
      "rsa.public_exponent",
      "rsa.ciphertexts"
    ],
    "signals": [
      {
        "id": "small-e",
        "when": {
          "fact": "rsa.public_exponent",
          "op": "eq",
          "value": 3
        },
        "weight": 20,
        "reason": "A low public exponent is a broadcast signal."
      }
    ],
    "requires": [
      {
        "id": "moduli-present",
        "when": {
          "fact": "rsa.moduli",
          "op": "exists"
        },
        "reason": "CRT needs every public modulus."
      }
    ],
    "rejects": [],
    "negative_matches": [],
    "cheap_probes": [
      {
        "id": "pairwise-gcd",
        "instruction": "Check every modulus pair for a non-trivial gcd.",
        "max_seconds": 10,
        "produces_facts": ["rsa.moduli_pairwise_coprime"]
      }
    ],
    "expected_cost": {
      "class": "low",
      "notes": "CRT and exact integer roots are fast."
    },
    "tooling": [
      {
        "command": "python3",
        "required": true,
        "packages": [],
        "reason": "The reference implementation uses integer arithmetic."
      }
    ],
    "template": null,
    "procedure": [
      {
        "id": "combine",
        "instruction": "Use CRT and require an exact cube root."
      }
    ],
    "citations": [
      {
        "kind": "paper",
        "paper_id": "doi:10.1007/3-540-39799-X_29",
        "title": "On using RSA with low exponent in a public key network",
        "url": "https://doi.org/10.1007/3-540-39799-X_29",
        "year": 1985,
        "section": "Broadcast attack",
        "assumptions": ["The ciphertexts encode one message under coprime moduli."],
        "verified_on": "2026-08-20"
      }
    ],
    "examples": [
      {
        "challenge_id": "example-broadcast",
        "event": "Schema example",
        "year": 2026,
        "source_kind": "remote",
        "repo_url": "https://github.com/example/example",
        "repo_sha": "8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac",
        "source_path": "challenge.py",
        "source_lines": "L1-L20",
        "inference_level": "direct"
      }
    ],
    "verification": [
      {
        "kind": "equation",
        "instruction": "Re-encrypt the recovered message under every modulus."
      }
    ]
  }
]
```

## Rank report

The ranker accepts a catalog only when every card declares the same schema
version. A mixed catalog fails at the first differing card with
`mixed-schema-versions`. The fingerprint version must then equal the catalog
version; a mismatch fails with `schema-version-mismatch`. Compatible canonical v1/v1 and
v2/v2 inputs produce a report carrying that declared version. The CLI digests
the exact decoded fingerprint and catalog JSON inputs, so the internal v1
example migration never rewrites either digest. The version-aware library
serializer restores the corresponding accepted v1 or v2 structural shape;
this does not promise byte-for-byte preservation of source JSON formatting.

The ranker emits a versioned report with those SHA-256 digests plus `eligible`,
`blocked`, and `rejected` arrays. An eligible result includes `card_id`, signed integer `score`,
`matched_signals`, `unmatched_signals`, `evidence_fact_ids`, and
`required_tools`. Every blocked or rejected entry has exactly `card_id`,
`rule_id`, `reason`, and `evidence_fact_ids`. `rule_id` is the stable ID of the
requirement, rejection rule, negative match, or tool condition that determined
the state; `reason` is that rule's human-readable explanation; and
`evidence_fact_ids` lists the observed or derived facts used for the decision.
The complete JSON below is parseable and illustrates every public entry shape.

```json
{
  "schema_version": 2,
  "fingerprint_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "catalog_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "eligible": [
    {
      "card_id": "rsa.hastad.broadcast",
      "score": 20,
      "matched_signals": ["small-e"],
      "unmatched_signals": [],
      "evidence_fact_ids": ["fact-001"],
      "required_tools": ["python3"]
    }
  ],
  "blocked": [
    {
      "card_id": "lattice.coppersmith.univariate-small-root",
      "rule_id": "root-bound-known",
      "reason": "The unknown-root bound is absent.",
      "evidence_fact_ids": []
    }
  ],
  "rejected": [
    {
      "card_id": "rsa.hastad.broadcast",
      "rule_id": "moduli-are-coprime",
      "reason": "A shared factor was found between two moduli.",
      "evidence_fact_ids": ["fact-moduli"]
    }
  ]
}
```

## Stable diagnostics

The parser reports a single first failure. Important diagnostic codes are
`input-unreadable`, `invalid-json`, `unknown-schema-version`,
`duplicate-fact-id`, `duplicate-fact-key`, `duplicate-card-id`, `unknown-fact-key`,
`unknown-operator`, `boolean-nesting-too-deep`, `invalid-signal-weight`,
`invalid-template-path`, `missing-citation-identifier`, and
`research-card-missing-pinned-example`. Source-boundary diagnostics include
`invalid-citation-url`, `invalid-repository-url`, `invalid-source-anchor`,
`invalid-source-lines`, and `invalid-local-example`. Version-boundary
diagnostics include `mixed-schema-versions` and `schema-version-mismatch`.
`input-undecodable` and
`input-too-deep` normalize expected untrusted input boundary failures;
`non-finite-number` rejects non-finite decoded programmatic values.
`invalid-card-id` is used for a card ID outside the lowercase dotted/hyphenated
grammar. Unknown fields, missing fields, type errors, self references, and
derived-evidence cycles are also rejected rather than ignored.
