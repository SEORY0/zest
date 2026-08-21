# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Fingerprint JSON-to-domain parsing for Zest crypto fingerprints."""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Set, Tuple

from zest_crypto_types import (
    Capability,
    Constraints,
    Evidence,
    Fact,
    FactId,
    FactKey,
    FactStatus,
    Fingerprint,
    InputArtifact,
    JsonValue,
)
from zest_crypto_source import is_canonical_source_anchor
from zest_crypto_parse_values import (
    FACT_VALUE_TYPES_BY_SCHEMA,
    SHA256_RE,
    VALUE_TYPES,
    _array,
    _check_schema_version,
    _check_unique,
    _fail,
    _integer,
    _object,
    _parse_case_relative_path,
    _parse_fact_value,
    _string,
)


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


def parse_fingerprint(raw: JsonValue) -> Fingerprint:
    """Parse one decoded fingerprint object into immutable domain values."""

    value = _object(
        raw,
        "$",
        ("schema_version", "case_id", "inputs", "facts", "capabilities", "constraints"),
        ("schema_version", "case_id", "inputs", "facts", "capabilities", "constraints"),
    )
    schema_version = _check_schema_version(value["schema_version"], "$.schema_version")
    fact_value_types = FACT_VALUE_TYPES_BY_SCHEMA[schema_version]
    inputs = tuple(_parse_input(item, "$.inputs[{0}]".format(index)) for index, item in enumerate(_array(value["inputs"], "$.inputs")))
    _check_unique([item.id for item in inputs], "$.inputs", "duplicate-input-id")

    facts: List[Fact] = []
    for index, item in enumerate(_array(value["facts"], "$.facts")):
        path = "$.facts[{0}]".format(index)
        item_value = _object(item, path, ("id", "key", "value", "value_type", "status", "evidence"), ("id", "key", "value", "value_type", "status", "evidence"))
        key_value = _string(item_value["key"], path + ".key", "invalid-fact-key")
        if key_value not in fact_value_types:
            _fail(path + ".key", "unknown-fact-key", "fact key is not in schema version {0}".format(schema_version))
        value_type = _string(item_value["value_type"], path + ".value_type", "invalid-value-type")
        if value_type not in VALUE_TYPES:
            _fail(path + ".value_type", "invalid-value-type", "value type is not supported")
        expected_type = fact_value_types[key_value]
        if value_type != expected_type:
            _fail(path + ".value_type", "fact-value-type-mismatch", "{0} facts require {1}".format(key_value, expected_type))
        try:
            status = FactStatus(item_value["status"])
        except (TypeError, ValueError):
            _fail(path + ".status", "invalid-fact-status", "expected observed, derived, or inferred")
        parsed_fact_value = _parse_fact_value(item_value["value"], value_type, path + ".value")
        if key_value == "construction.source_anchors":
            for anchor_index, anchor in enumerate(parsed_fact_value):
                if not is_canonical_source_anchor(anchor):
                    _fail(
                        "{0}.value[{1}]".format(path, anchor_index),
                        "invalid-source-anchor",
                        "expected canonical host/owner/repo@40-hex-SHA/path:Lx-Ly",
                    )
        facts.append(
            Fact(
                id=FactId(_string(item_value["id"], path + ".id")),
                key=FactKey(key_value),
                value=parsed_fact_value,
                status=status,
                evidence=_parse_evidence(item_value["evidence"], path + ".evidence", status),
            )
        )
    _check_unique([str(item.id) for item in facts], "$.facts", "duplicate-fact-id")
    _check_unique_fact_keys(facts)
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
        ("network", "oracle_access", "max_seconds", "max_memory_mb", "max_oracle_queries"),
        (),
    )
    network = constraints_value.get("network", "disabled")
    if network not in ("disabled", "allowed"):
        _fail("$.constraints.network", "invalid-network-constraint", "expected disabled or allowed")
    oracle_access = constraints_value.get("oracle_access", "disabled")
    if oracle_access not in ("disabled", "allowed"):
        _fail("$.constraints.oracle_access", "invalid-oracle-access-constraint", "expected disabled or allowed")
    constraints = Constraints(
        network=network,
        max_seconds=_optional_nonnegative_integer(constraints_value, "max_seconds", "$.constraints"),
        max_memory_mb=_optional_nonnegative_integer(constraints_value, "max_memory_mb", "$.constraints"),
        max_oracle_queries=_optional_nonnegative_integer(constraints_value, "max_oracle_queries", "$.constraints"),
        oracle_access=oracle_access,
    )
    return Fingerprint(schema_version, _string(value["case_id"], "$.case_id"), inputs, tuple(facts), tuple(capabilities), constraints)


def _check_unique_fact_keys(facts: Sequence[Fact]) -> None:
    seen: Set[FactKey] = set()
    for index, fact in enumerate(facts):
        if fact.key in seen:
            _fail("$.facts[{0}].key".format(index), "duplicate-fact-key", "fact keys must be unique for the FactIndex")
        seen.add(fact.key)


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
