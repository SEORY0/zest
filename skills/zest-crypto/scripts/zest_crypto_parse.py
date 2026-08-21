# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Strict JSON-to-domain parsing for Zest crypto fingerprints and AttackCards.

JSON decoding belongs to the command boundary.  The public parsing functions
accept already-decoded values so callers cannot accidentally decode nested JSON
or turn malformed boundary data into trusted domain objects.
"""

from __future__ import annotations

import math
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

from zest_crypto_types import (
    AttackCard,
    Capability,
    CardId,
    CatalogIssue,
    CheapProbe,
    Citation,
    Condition,
    Constraints,
    Cost,
    CostClass,
    Evidence,
    Fact,
    FactId,
    FactKey,
    FactStatus,
    FactValue,
    Fingerprint,
    InputArtifact,
    JsonValue,
    NegativeMatch,
    Operator,
    ParseError,
    PinnedExample,
    ProcedureStep,
    Rule,
    Signal,
    ToolRequirement,
    VerificationStep,
)


SCHEMA_VERSION = 1

FACT_VALUE_TYPES: Dict[str, str] = {
    "rsa.modulus": "integer",
    "rsa.moduli": "integer_list",
    "rsa.public_exponent": "integer",
    "rsa.public_exponents": "integer_list",
    "rsa.ciphertexts": "integer_list",
    "rsa.same_plaintext": "boolean",
    "rsa.message_relation_type": "string",
    "rsa.moduli_pairwise_coprime": "boolean",
    "rsa.exponents_coprime": "boolean",
    "rsa.public_exponent_ratio": "number",
    "rsa.factorization_verified": "boolean",
    "rsa.private_exponent": "integer",
    "lattice.polynomial": "string",
    "lattice.modulus": "integer",
    "lattice.unknown_bound": "integer",
    "signature.scheme": "string",
    "signature.sample_count": "integer",
    "signature.public_key_present": "boolean",
    "signature.repeated_r": "boolean",
    "signature.nonce_leak_bits": "integer",
    "signature.nonce_bias_bound": "integer",
    "signature.nonce_recurrence": "string",
    "prng.family": "string",
    "prng.output_count": "integer",
    "prng.output_word_bits": "integer",
    "prng.outputs_aligned": "boolean",
    "oracle.kind": "string",
    "oracle.distinguishable_response": "boolean",
    "oracle.chosen_ciphertext": "boolean",
    "oracle.query_budget": "integer",
    "construction.canonical_family": "string",
    "construction.paper_ids": "string_list",
    "construction.source_anchors": "string_list",
    "construction.parameter_signature": "string_list",
    "construction.toy_invariant_verified": "boolean",
    "construction.negative_matches_checked": "string_list",
}

VALUE_TYPES = frozenset(("boolean", "integer", "number", "string", "integer_list", "string_list"))
CARD_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
NUMERIC_VALUE_TYPES = frozenset(("integer", "number"))
CONTAINS_VALUE_TYPES = frozenset(("string", "integer_list", "string_list"))
LENGTH_VALUE_TYPES = CONTAINS_VALUE_TYPES


def _fail(path: str, code: str, detail: str) -> None:
    raise ParseError(path=path, code=code, detail=detail)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _string(value: Any, path: str, code: str = "invalid-string") -> str:
    if not isinstance(value, str) or not value:
        _fail(path, code, "expected a non-empty string")
    return value


def _integer(value: Any, path: str, minimum: int = None) -> int:
    if not _is_int(value):
        _fail(path, "invalid-integer", "expected an integer")
    if minimum is not None and value < minimum:
        _fail(path, "invalid-integer", "expected an integer greater than or equal to {0}".format(minimum))
    return value


def _object(raw: Any, path: str, allowed: Iterable[str], required: Iterable[str]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        _fail(path, "invalid-object", "expected an object")
    allowed_names = set(allowed)
    unexpected = sorted(set(raw).difference(allowed_names))
    if unexpected:
        _fail("{0}.{1}".format(path, unexpected[0]), "unknown-field", "field is not part of this schema")
    missing = sorted(set(required).difference(raw))
    if missing:
        _fail("{0}.{1}".format(path, missing[0]), "missing-field", "field is required")
    return raw


def _array(raw: Any, path: str) -> List[Any]:
    if not isinstance(raw, list):
        _fail(path, "invalid-array", "expected an array")
    return raw


def _string_array(raw: Any, path: str, nonempty: bool = False) -> Tuple[str, ...]:
    values = _array(raw, path)
    if nonempty and not values:
        _fail(path, "empty-array", "expected at least one item")
    return tuple(_string(value, "{0}[{1}]".format(path, index)) for index, value in enumerate(values))


def _check_schema_version(value: Any, path: str) -> int:
    version = _integer(value, path, 1)
    if version != SCHEMA_VERSION:
        _fail(path, "unknown-schema-version", "supported schema version is {0}".format(SCHEMA_VERSION))
    return version


def _check_unique(values: Sequence[str], path: str, code: str) -> None:
    seen: Set[str] = set()
    for index, value in enumerate(values):
        if value in seen:
            _fail("{0}[{1}]".format(path, index), code, "identifier appears more than once")
        seen.add(value)


def _parse_fact_value(raw: Any, value_type: str, path: str) -> FactValue:
    if value_type == "boolean":
        if not isinstance(raw, bool):
            _fail(path, "invalid-fact-value", "expected a boolean")
        return raw
    if value_type == "integer":
        return _integer(raw, path)
    if value_type == "number":
        if not (_is_int(raw) or isinstance(raw, float)):
            _fail(path, "invalid-fact-value", "expected a number")
        if isinstance(raw, float) and not math.isfinite(raw):
            _fail(path, "non-finite-number", "expected a finite number")
        return raw
    if value_type == "string":
        return _string(raw, path, "invalid-fact-value")
    if value_type == "integer_list":
        return tuple(_integer(value, "{0}[{1}]".format(path, index)) for index, value in enumerate(_array(raw, path)))
    if value_type == "string_list":
        return tuple(_string(value, "{0}[{1}]".format(path, index), "invalid-fact-value") for index, value in enumerate(_array(raw, path)))
    _fail(path, "invalid-value-type", "unknown fact value type")
    raise AssertionError("unreachable")


def _parse_evidence(raw: Any, path: str, status: FactStatus) -> Evidence:
    value = _object(raw, path, ("input_id", "locator", "source_fact_ids", "rationale"), ())
    input_id = value.get("input_id")
    locator = value.get("locator")
    rationale = value.get("rationale")
    source_fact_ids = value.get("source_fact_ids", [])
    if input_id is not None:
        input_id = _string(input_id, path + ".input_id")
    if locator is not None:
        locator = _string(locator, path + ".locator")
    if rationale is not None:
        rationale = _string(rationale, path + ".rationale")
    parsed_source_ids = tuple(
        FactId(_string(item, "{0}.source_fact_ids[{1}]".format(path, index)))
        for index, item in enumerate(_array(source_fact_ids, path + ".source_fact_ids"))
    )
    if status is FactStatus.OBSERVED and (input_id is None or locator is None):
        _fail(path, "invalid-evidence", "observed facts require input_id and locator")
    if status is FactStatus.DERIVED and (not parsed_source_ids or rationale is None):
        _fail(path, "invalid-evidence", "derived facts require source_fact_ids and rationale")
    if status is FactStatus.INFERRED and rationale is None:
        _fail(path, "invalid-evidence", "inferred facts require a rationale")
    return Evidence(input_id, locator, parsed_source_ids, rationale)


def _parse_input(raw: Any, path: str) -> InputArtifact:
    value = _object(raw, path, ("id", "path", "sha256", "media_type"), ("id", "path", "sha256", "media_type"))
    digest = _string(value["sha256"], path + ".sha256", "invalid-sha256")
    if not SHA256_RE.fullmatch(digest):
        _fail(path + ".sha256", "invalid-sha256", "expected 64 lowercase hexadecimal characters")
    return InputArtifact(
        id=_string(value["id"], path + ".id"),
        path=_parse_case_relative_path(value["path"], path + ".path", "invalid-input-path"),
        sha256=digest,
        media_type=_string(value["media_type"], path + ".media_type"),
    )


def _parse_case_relative_path(raw: Any, path: str, code: str) -> str:
    value = _string(raw, path, code)
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or windows.root
        or "\x00" in value
        or "\\" in value
        or ".." in posix.parts
        or ".." in windows.parts
    ):
        _fail(path, code, "path must be relative and may not traverse its parent")
    if str(posix) != value or value in (".", ""):
        _fail(path, code, "path must be a normalized non-empty relative path")
    return value


def parse_fingerprint(raw: JsonValue) -> Fingerprint:
    """Parse one decoded fingerprint object into immutable domain values."""

    value = _object(
        raw,
        "$",
        ("schema_version", "case_id", "inputs", "facts", "capabilities", "constraints"),
        ("schema_version", "case_id", "inputs", "facts", "capabilities", "constraints"),
    )
    schema_version = _check_schema_version(value["schema_version"], "$.schema_version")
    inputs = tuple(_parse_input(item, "$.inputs[{0}]".format(index)) for index, item in enumerate(_array(value["inputs"], "$.inputs")))
    _check_unique([item.id for item in inputs], "$.inputs", "duplicate-input-id")

    facts: List[Fact] = []
    for index, item in enumerate(_array(value["facts"], "$.facts")):
        path = "$.facts[{0}]".format(index)
        item_value = _object(item, path, ("id", "key", "value", "value_type", "status", "evidence"), ("id", "key", "value", "value_type", "status", "evidence"))
        key_value = _string(item_value["key"], path + ".key", "invalid-fact-key")
        if key_value not in FACT_VALUE_TYPES:
            _fail(path + ".key", "unknown-fact-key", "fact key is not in schema version {0}".format(SCHEMA_VERSION))
        value_type = _string(item_value["value_type"], path + ".value_type", "invalid-value-type")
        if value_type not in VALUE_TYPES:
            _fail(path + ".value_type", "invalid-value-type", "value type is not supported")
        expected_type = FACT_VALUE_TYPES[key_value]
        if value_type != expected_type:
            _fail(path + ".value_type", "fact-value-type-mismatch", "{0} facts require {1}".format(key_value, expected_type))
        try:
            status = FactStatus(item_value["status"])
        except (TypeError, ValueError):
            _fail(path + ".status", "invalid-fact-status", "expected observed, derived, or inferred")
        facts.append(
            Fact(
                id=FactId(_string(item_value["id"], path + ".id")),
                key=FactKey(key_value),
                value=_parse_fact_value(item_value["value"], value_type, path + ".value"),
                status=status,
                evidence=_parse_evidence(item_value["evidence"], path + ".evidence", status),
            )
        )
    _check_unique([str(item.id) for item in facts], "$.facts", "duplicate-fact-id")
    input_ids = frozenset(item.id for item in inputs)
    for index, fact in enumerate(facts):
        if fact.status is FactStatus.OBSERVED and fact.evidence.input_id not in input_ids:
            _fail("$.facts[{0}].evidence.input_id".format(index), "unknown-input-id", "evidence must name a fingerprint input")
    fact_ids = frozenset(item.id for item in facts)
    derived_dependencies: Dict[FactId, Tuple[FactId, ...]] = {}
    for index, fact in enumerate(facts):
        for source_index, source_id in enumerate(fact.evidence.source_fact_ids):
            source_path = "$.facts[{0}].evidence.source_fact_ids[{1}]".format(index, source_index)
            if source_id not in fact_ids:
                _fail(source_path, "unknown-source-fact-id", "derived evidence must name a fingerprint fact")
            if source_id == fact.id:
                _fail(source_path, "self-referential-derived-fact", "a derived fact may not cite itself")
        if fact.status is FactStatus.DERIVED:
            derived_dependencies[fact.id] = fact.evidence.source_fact_ids
    _reject_derived_fact_cycles(facts, derived_dependencies)

    capabilities: List[Capability] = []
    for index, item in enumerate(_array(value["capabilities"], "$.capabilities")):
        path = "$.capabilities[{0}]".format(index)
        item_value = _object(item, path, ("command", "available", "version"), ("command", "available", "version"))
        if not isinstance(item_value["available"], bool):
            _fail(path + ".available", "invalid-boolean", "expected a boolean")
        version = item_value["version"]
        if version is not None:
            version = _string(version, path + ".version")
        capabilities.append(Capability(_string(item_value["command"], path + ".command"), item_value["available"], version))
    _check_unique([item.command for item in capabilities], "$.capabilities", "duplicate-capability-command")

    constraints_value = _object(
        value["constraints"],
        "$.constraints",
        ("network", "max_seconds", "max_memory_mb", "max_oracle_queries"),
        (),
    )
    network = constraints_value.get("network", "disabled")
    if network not in ("disabled", "allowed"):
        _fail("$.constraints.network", "invalid-network-constraint", "expected disabled or allowed")
    constraints = Constraints(
        network=network,
        max_seconds=_optional_nonnegative_integer(constraints_value, "max_seconds", "$.constraints"),
        max_memory_mb=_optional_nonnegative_integer(constraints_value, "max_memory_mb", "$.constraints"),
        max_oracle_queries=_optional_nonnegative_integer(constraints_value, "max_oracle_queries", "$.constraints"),
    )
    return Fingerprint(schema_version, _string(value["case_id"], "$.case_id"), inputs, tuple(facts), tuple(capabilities), constraints)


def _optional_nonnegative_integer(value: Dict[str, Any], key: str, path: str) -> Any:
    raw = value.get(key)
    if raw is None:
        return None
    return _integer(raw, path + "." + key, 0)


def _reject_derived_fact_cycles(facts: Sequence[Fact], dependencies: Dict[FactId, Tuple[FactId, ...]]) -> None:
    unresolved = set(dependencies)
    while unresolved:
        ready = [fact_id for fact_id in unresolved if not unresolved.intersection(dependencies[fact_id])]
        if ready:
            unresolved.difference_update(ready)
            continue
        for index, fact in enumerate(facts):
            if fact.id not in unresolved:
                continue
            for source_index, source_id in enumerate(fact.evidence.source_fact_ids):
                if source_id in unresolved:
                    _fail(
                        "$.facts[{0}].evidence.source_fact_ids[{1}]".format(index, source_index),
                        "cyclic-derived-facts",
                        "derived evidence may not form a cycle",
                    )
        raise AssertionError("unreachable")


def _parse_condition(raw: Any, path: str, boolean_depth: int = 0) -> Condition:
    value = _object(raw, path, ("fact", "op", "value", "all", "any", "not"), ())
    names = set(value)
    group_names = names.intersection(("all", "any", "not"))
    if group_names:
        if names != group_names or len(group_names) != 1:
            _fail(path, "invalid-condition", "a boolean condition contains exactly one of all, any, or not")
        if boolean_depth >= 2:
            _fail(path, "boolean-nesting-too-deep", "boolean groups may nest no deeper than two levels")
        group_name = next(iter(group_names))
        group_path = path + "." + group_name
        if group_name == "not":
            return Condition(None, None, None, (), (), _parse_condition(value[group_name], group_path, boolean_depth + 1))
        children = _array(value[group_name], group_path)
        if not children:
            _fail(group_path, "empty-condition-group", "boolean condition groups require at least one condition")
        parsed = tuple(_parse_condition(item, "{0}[{1}]".format(group_path, index), boolean_depth + 1) for index, item in enumerate(children))
        if group_name == "all":
            return Condition(None, None, None, parsed, (), None)
        return Condition(None, None, None, (), parsed, None)
    if names.difference(("fact", "op", "value")) or "fact" not in value or "op" not in value:
        _fail(path, "invalid-condition", "a predicate requires fact and op")
    fact_key = _string(value["fact"], path + ".fact", "invalid-fact-key")
    if fact_key not in FACT_VALUE_TYPES:
        _fail(path + ".fact", "unknown-fact-key", "fact key is not in schema version {0}".format(SCHEMA_VERSION))
    try:
        operator = Operator(value["op"])
    except (TypeError, ValueError):
        _fail(path + ".op", "unknown-operator", "operator is not supported")
    if operator is Operator.EXISTS:
        if "value" in value:
            _fail(path + ".value", "invalid-condition-value", "exists does not accept a value")
        return Condition(FactKey(fact_key), operator, None, (), (), None)
    if "value" not in value:
        _fail(path + ".value", "missing-field", "predicate value is required")
    return Condition(FactKey(fact_key), operator, _parse_condition_value(value["value"], FACT_VALUE_TYPES[fact_key], operator, path + ".value"), (), (), None)


def _parse_condition_value(raw: Any, value_type: str, operator: Operator, path: str) -> FactValue:
    if operator in (Operator.EQ, Operator.NEQ):
        return _parse_fact_value(raw, value_type, path)
    if operator in (Operator.LT, Operator.LTE, Operator.GT, Operator.GTE):
        if value_type not in NUMERIC_VALUE_TYPES:
            _fail(path, "invalid-condition-value", "comparison operators require numeric facts")
        return _parse_fact_value(raw, value_type, path)
    if operator is Operator.IN:
        values = _array(raw, path)
        if not values:
            _fail(path, "empty-array", "in requires at least one candidate value")
        element_type = "string" if value_type == "string_list" else "integer" if value_type == "integer_list" else value_type
        return tuple(_parse_fact_value(item, element_type, "{0}[{1}]".format(path, index)) for index, item in enumerate(values))
    if operator is Operator.CONTAINS:
        if value_type not in CONTAINS_VALUE_TYPES:
            _fail(path, "invalid-condition-value", "contains requires a string or list fact")
        if value_type == "string":
            return _parse_fact_value(raw, "string", path)
        if value_type == "integer_list":
            return _parse_fact_value(raw, "integer", path)
        if value_type == "string_list":
            return _parse_fact_value(raw, "string", path)
    if operator in (Operator.LEN_EQ, Operator.LEN_GTE):
        if value_type not in LENGTH_VALUE_TYPES:
            _fail(path, "invalid-condition-value", "length operators require a string or list fact")
        return _integer(raw, path, 0)
    _fail(path, "unknown-operator", "operator is not supported")
    raise AssertionError("unreachable")


def _parse_rule(raw: Any, path: str) -> Rule:
    value = _object(raw, path, ("id", "when", "reason"), ("id", "when", "reason"))
    return Rule(_string(value["id"], path + ".id"), _parse_condition(value["when"], path + ".when"), _string(value["reason"], path + ".reason"))


def _parse_signal(raw: Any, path: str) -> Signal:
    value = _object(raw, path, ("id", "when", "weight", "reason"), ("id", "when", "weight", "reason"))
    weight = _integer(value["weight"], path + ".weight")
    if weight < -100 or weight > 100:
        _fail(path + ".weight", "invalid-signal-weight", "weight must be between -100 and 100")
    return Signal(_string(value["id"], path + ".id"), _parse_condition(value["when"], path + ".when"), weight, _string(value["reason"], path + ".reason"))


def _parse_negative_match(raw: Any, path: str) -> NegativeMatch:
    value = _object(raw, path, ("id", "when", "reason", "unknown_policy"), ("id", "when", "reason", "unknown_policy"))
    policy = value["unknown_policy"]
    if policy not in ("ignore", "block"):
        _fail(path + ".unknown_policy", "invalid-unknown-policy", "expected ignore or block")
    return NegativeMatch(
        _string(value["id"], path + ".id"),
        _parse_condition(value["when"], path + ".when"),
        _string(value["reason"], path + ".reason"),
        policy,
    )


def _parse_cost(raw: Any, path: str) -> Cost:
    value = _object(raw, path, ("class", "notes"), ("class", "notes"))
    try:
        cost_class = CostClass(value["class"])
    except (TypeError, ValueError):
        _fail(path + ".class", "invalid-cost-class", "expected low, medium, high, or oracle-bound")
    return Cost(cost_class, _string(value["notes"], path + ".notes"))


def _parse_tool(raw: Any, path: str) -> ToolRequirement:
    value = _object(raw, path, ("command", "required", "packages", "reason"), ("command", "required", "packages", "reason"))
    if not isinstance(value["required"], bool):
        _fail(path + ".required", "invalid-boolean", "expected a boolean")
    return ToolRequirement(
        _string(value["command"], path + ".command"),
        value["required"],
        _string_array(value["packages"], path + ".packages"),
        _string(value["reason"], path + ".reason"),
    )


def _parse_template(raw: Any, path: str) -> Any:
    if raw is None:
        return None
    return _parse_case_relative_path(raw, path, "invalid-template-path")


def _parse_citation(raw: Any, path: str) -> Citation:
    if not isinstance(raw, dict):
        _fail(path, "invalid-object", "expected an object")
    paper_id = raw.get("paper_id")
    if not isinstance(paper_id, str) or not paper_id.strip():
        _fail(path + ".paper_id", "missing-citation-identifier", "citations require a non-empty paper_id")
    value = _object(raw, path, ("kind", "paper_id", "title", "url", "year", "section", "assumptions", "verified_on"), ("kind", "paper_id", "title", "url", "year", "section", "assumptions", "verified_on"))
    url = _string(value["url"], path + ".url")
    if not url.startswith("https://"):
        _fail(path + ".url", "invalid-citation-url", "citation URLs must use https")
    return Citation(
        _string(value["kind"], path + ".kind"),
        paper_id,
        _string(value["title"], path + ".title"),
        url,
        _integer(value["year"], path + ".year", 1),
        _string(value["section"], path + ".section"),
        _string_array(value["assumptions"], path + ".assumptions", True),
        _string(value["verified_on"], path + ".verified_on"),
    )


def _parse_example(raw: Any, path: str) -> PinnedExample:
    value = _object(
        raw,
        path,
        ("challenge_id", "event", "year", "repo_url", "repo_sha", "source_path", "source_lines", "inference_level"),
        ("challenge_id", "event", "year", "repo_url", "repo_sha", "source_path", "source_lines", "inference_level"),
    )
    repo_sha = _string(value["repo_sha"], path + ".repo_sha", "invalid-repository-sha")
    if not GIT_SHA_RE.fullmatch(repo_sha):
        _fail(path + ".repo_sha", "invalid-repository-sha", "expected a 40-character lowercase commit SHA")
    repo_url = _string(value["repo_url"], path + ".repo_url")
    if not repo_url.startswith("https://"):
        _fail(path + ".repo_url", "invalid-repository-url", "pinned repository URLs must use https")
    level = value["inference_level"]
    if level not in ("direct", "inferred"):
        _fail(path + ".inference_level", "invalid-inference-level", "expected direct or inferred")
    return PinnedExample(
        _string(value["challenge_id"], path + ".challenge_id"),
        _string(value["event"], path + ".event"),
        _integer(value["year"], path + ".year", 1),
        repo_url,
        repo_sha,
        _parse_case_relative_path(value["source_path"], path + ".source_path", "invalid-source-path"),
        _string(value["source_lines"], path + ".source_lines"),
        level,
    )


def _parse_probe(raw: Any, path: str) -> CheapProbe:
    value = _object(raw, path, ("id", "instruction", "max_seconds", "produces_facts"), ("id", "instruction", "max_seconds", "produces_facts"))
    produced = []
    for index, key in enumerate(_string_array(value["produces_facts"], path + ".produces_facts")):
        if key not in FACT_VALUE_TYPES:
            _fail("{0}.produces_facts[{1}]".format(path, index), "unknown-fact-key", "fact key is not in schema version {0}".format(SCHEMA_VERSION))
        produced.append(FactKey(key))
    return CheapProbe(
        _string(value["id"], path + ".id"),
        _string(value["instruction"], path + ".instruction"),
        _integer(value["max_seconds"], path + ".max_seconds", 0),
        tuple(produced),
    )


def _parse_procedure_step(raw: Any, path: str) -> ProcedureStep:
    value = _object(raw, path, ("id", "instruction"), ("id", "instruction"))
    return ProcedureStep(_string(value["id"], path + ".id"), _string(value["instruction"], path + ".instruction"))


def _parse_verification_step(raw: Any, path: str) -> VerificationStep:
    value = _object(raw, path, ("kind", "instruction"), ("kind", "instruction"))
    return VerificationStep(_string(value["kind"], path + ".kind"), _string(value["instruction"], path + ".instruction"))


def _parse_card(raw: Any, path: str) -> AttackCard:
    if not isinstance(raw, dict):
        _fail(path, "invalid-object", "expected an AttackCard object")
    card_id = raw.get("id")
    if not isinstance(card_id, str) or not CARD_ID_RE.fullmatch(card_id):
        _fail(path + ".id", "invalid-card-id", "card IDs use lowercase segments separated by dots or hyphens")
    value = _object(
        raw,
        path,
        (
            "schema_version", "id", "version", "title", "canonical_family_id", "family_aliases", "summary", "parameter_signature",
            "signals", "requires", "rejects", "negative_matches", "cheap_probes", "expected_cost", "tooling", "template",
            "procedure", "citations", "examples", "verification",
        ),
        (
            "schema_version", "id", "version", "title", "canonical_family_id", "family_aliases", "summary", "parameter_signature",
            "signals", "requires", "rejects", "negative_matches", "cheap_probes", "expected_cost", "tooling", "template",
            "procedure", "citations", "examples", "verification",
        ),
    )
    schema_version = _check_schema_version(value["schema_version"], path + ".schema_version")
    parameter_signature = []
    for index, key in enumerate(_string_array(value["parameter_signature"], path + ".parameter_signature")):
        if key not in FACT_VALUE_TYPES:
            _fail("{0}.parameter_signature[{1}]".format(path, index), "unknown-fact-key", "fact key is not in schema version {0}".format(SCHEMA_VERSION))
        parameter_signature.append(FactKey(key))
    signals = tuple(_parse_signal(item, "{0}.signals[{1}]".format(path, index)) for index, item in enumerate(_array(value["signals"], path + ".signals")))
    _check_unique([item.id for item in signals], path + ".signals", "duplicate-signal-id")
    requires = tuple(_parse_rule(item, "{0}.requires[{1}]".format(path, index)) for index, item in enumerate(_array(value["requires"], path + ".requires")))
    rejects = tuple(_parse_rule(item, "{0}.rejects[{1}]".format(path, index)) for index, item in enumerate(_array(value["rejects"], path + ".rejects")))
    negative_matches = tuple(_parse_negative_match(item, "{0}.negative_matches[{1}]".format(path, index)) for index, item in enumerate(_array(value["negative_matches"], path + ".negative_matches")))
    _check_unique([item.id for item in requires], path + ".requires", "duplicate-rule-id")
    _check_unique([item.id for item in rejects], path + ".rejects", "duplicate-rule-id")
    _check_unique([item.id for item in negative_matches], path + ".negative_matches", "duplicate-negative-match-id")
    probes = tuple(_parse_probe(item, "{0}.cheap_probes[{1}]".format(path, index)) for index, item in enumerate(_array(value["cheap_probes"], path + ".cheap_probes")))
    procedure = tuple(_parse_procedure_step(item, "{0}.procedure[{1}]".format(path, index)) for index, item in enumerate(_array(value["procedure"], path + ".procedure")))
    citations = tuple(_parse_citation(item, "{0}.citations[{1}]".format(path, index)) for index, item in enumerate(_array(value["citations"], path + ".citations")))
    if not citations:
        _fail(path + ".citations", "missing-citation-identifier", "AttackCards require at least one citation")
    examples = tuple(_parse_example(item, "{0}.examples[{1}]".format(path, index)) for index, item in enumerate(_array(value["examples"], path + ".examples")))
    if card_id.startswith("paper.") and not examples:
        _fail(path + ".examples", "research-card-missing-pinned-example", "research-tier cards require a pinned example")
    verification = tuple(_parse_verification_step(item, "{0}.verification[{1}]".format(path, index)) for index, item in enumerate(_array(value["verification"], path + ".verification")))
    return AttackCard(
        id=CardId(card_id),
        version=_integer(value["version"], path + ".version", 1),
        canonical_family_id=_string(value["canonical_family_id"], path + ".canonical_family_id"),
        signals=signals,
        requires=requires,
        rejects=rejects,
        negative_matches=negative_matches,
        expected_cost=_parse_cost(value["expected_cost"], path + ".expected_cost"),
        tooling=tuple(_parse_tool(item, "{0}.tooling[{1}]".format(path, index)) for index, item in enumerate(_array(value["tooling"], path + ".tooling"))),
        template=_parse_template(value["template"], path + ".template"),
        title=_string(value["title"], path + ".title"),
        family_aliases=_string_array(value["family_aliases"], path + ".family_aliases"),
        summary=_string(value["summary"], path + ".summary"),
        parameter_signature=tuple(parameter_signature),
        cheap_probes=probes,
        procedure=procedure,
        citations=citations,
        examples=examples,
        verification=verification,
    )


def parse_catalog(raw: JsonValue) -> Tuple[AttackCard, ...]:
    """Parse one decoded AttackCard JSON array into immutable domain values."""

    cards = tuple(_parse_card(item, "$[{0}]".format(index)) for index, item in enumerate(_array(raw, "$")))
    _check_unique([str(card.id) for card in cards], "$", "duplicate-card-id")
    return cards


def validate_catalog(cards: Tuple[AttackCard, ...], skill_root: Path) -> Tuple[CatalogIssue, ...]:
    """Return cross-card issues after parsing, without touching package contents."""

    root = skill_root.resolve()
    issues: List[CatalogIssue] = []
    for index, card in enumerate(cards):
        if card.template is None:
            continue
        resolved = (root / card.template).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            issues.append(CatalogIssue("$[{0}].template".format(index), "invalid-template-path", "template escapes skill root"))
    return tuple(issues)
