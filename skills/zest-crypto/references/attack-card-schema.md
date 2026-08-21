# AttackCard and fingerprint schema

The catalog and fingerprint formats are versioned JSON boundaries. Version `1`
is the only accepted version. Decode JSON once at the command boundary, then
pass the resulting JSON value to `parse_fingerprint` or `parse_catalog`; never
place serialized JSON inside a fact or card field.

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
schema_version: integer  (must be 1)
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
`max_oracle_queries` are non-negative integers when present.

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

Unknown keys and a mismatched `value_type` are rejected. Fact IDs and card IDs
must be unique within their enclosing arrays.

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

Each citation has `kind`, non-empty `paper_id`, `title`, HTTPS `url`, positive
`year`, `section`, non-empty string-array `assumptions`, and `verified_on`.
Each pinned example has `challenge_id`, `event`, positive `year`, HTTPS
`repo_url`, a 40-lowercase-hex `repo_sha`, normalized relative `source_path`,
`source_lines`, and `inference_level` (`direct` or `inferred`). Cards with IDs
starting `paper.` are research tier and require at least one pinned example.
`cheap_probes` have `id`, `instruction`, non-negative `max_seconds`, and
`produces_facts`; procedure entries have `id` and `instruction`; verification
entries have `kind` and `instruction`.

The following complete card is valid JSON and parses with `parse_catalog`:

```json
[
  {
    "schema_version": 1,
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

The ranker emits a versioned report with the SHA-256 digests of the exact
fingerprint and catalog JSON inputs, plus `eligible`, `blocked`, and `rejected`
arrays. An eligible result includes `card_id`, signed integer `score`,
`matched_signals`, `unmatched_signals`, `evidence_fact_ids`, and
`required_tools`. Every blocked or rejected entry has exactly `card_id`,
`rule_id`, `reason`, and `evidence_fact_ids`. `rule_id` is the stable ID of the
requirement, rejection rule, negative match, or tool condition that determined
the state; `reason` is that rule's human-readable explanation; and
`evidence_fact_ids` lists the observed or derived facts used for the decision.
The complete JSON below is parseable and illustrates every public entry shape.

```json
{
  "schema_version": 1,
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
`duplicate-fact-id`, `duplicate-card-id`, `unknown-fact-key`,
`unknown-operator`, `boolean-nesting-too-deep`, `invalid-signal-weight`,
`invalid-template-path`, `missing-citation-identifier`, and
`research-card-missing-pinned-example`. `input-undecodable` and
`input-too-deep` normalize expected untrusted input boundary failures;
`non-finite-number` rejects non-finite decoded programmatic values.
`invalid-card-id` is used for a card ID outside the lowercase dotted/hyphenated
grammar. Unknown fields, missing fields, type errors, self references, and
derived-evidence cycles are also rejected rather than ignored.
