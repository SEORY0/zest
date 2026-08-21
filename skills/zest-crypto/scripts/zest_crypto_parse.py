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

from pathlib import Path
from typing import Any, List, Tuple

from zest_crypto_types import (
    AttackCard,
    CardId,
    CatalogIssue,
    CheapProbe,
    Citation,
    Condition,
    Cost,
    CostClass,
    FactKey,
    FactValue,
    JsonValue,
    NegativeMatch,
    Operator,
    PinnedExample,
    ProcedureStep,
    Rule,
    Signal,
    ToolRequirement,
    VerificationStep,
)
from zest_crypto_source import (
    is_canonical_https_url,
    is_canonical_source_lines,
)
from zest_crypto_parse_values import (
    CANONICAL_PROVENANCE_SCHEMA_VERSIONS,
    CARD_ID_RE,
    CONTAINS_VALUE_TYPES,
    FACT_VALUE_TYPES,
    FACT_VALUE_TYPES_BY_SCHEMA,
    GIT_SHA_RE,
    LENGTH_VALUE_TYPES,
    NUMERIC_VALUE_TYPES,
    READ_ONLY_SCHEMA_VERSIONS,
    SCHEMA_VERSION,
    SHA256_RE,
    SUPPORTED_SCHEMA_VERSIONS,
    V1_FACT_VALUE_TYPES,
    V2_FACT_VALUE_TYPES,
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
    _string_array,
)
from zest_crypto_parse_fingerprint import parse_fingerprint


def _parse_condition(raw: Any, path: str, schema_version: int, boolean_depth: int = 0) -> Condition:
    fact_value_types = FACT_VALUE_TYPES_BY_SCHEMA[schema_version]
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
            return Condition(None, None, None, (), (), _parse_condition(value[group_name], group_path, schema_version, boolean_depth + 1))
        children = _array(value[group_name], group_path)
        if not children:
            _fail(group_path, "empty-condition-group", "boolean condition groups require at least one condition")
        parsed = tuple(_parse_condition(item, "{0}[{1}]".format(group_path, index), schema_version, boolean_depth + 1) for index, item in enumerate(children))
        if group_name == "all":
            return Condition(None, None, None, parsed, (), None)
        return Condition(None, None, None, (), parsed, None)
    if names.difference(("fact", "op", "value")) or "fact" not in value or "op" not in value:
        _fail(path, "invalid-condition", "a predicate requires fact and op")
    fact_key = _string(value["fact"], path + ".fact", "invalid-fact-key")
    if fact_key not in fact_value_types:
        _fail(path + ".fact", "unknown-fact-key", "fact key is not in schema version {0}".format(schema_version))
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
    return Condition(FactKey(fact_key), operator, _parse_condition_value(value["value"], fact_value_types[fact_key], operator, path + ".value"), (), (), None)


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


def _parse_rule(raw: Any, path: str, schema_version: int) -> Rule:
    value = _object(raw, path, ("id", "when", "reason"), ("id", "when", "reason"))
    return Rule(_string(value["id"], path + ".id"), _parse_condition(value["when"], path + ".when", schema_version), _string(value["reason"], path + ".reason"))


def _parse_signal(raw: Any, path: str, schema_version: int) -> Signal:
    value = _object(raw, path, ("id", "when", "weight", "reason"), ("id", "when", "weight", "reason"))
    weight = _integer(value["weight"], path + ".weight")
    if weight < -100 or weight > 100:
        _fail(path + ".weight", "invalid-signal-weight", "weight must be between -100 and 100")
    return Signal(_string(value["id"], path + ".id"), _parse_condition(value["when"], path + ".when", schema_version), weight, _string(value["reason"], path + ".reason"))


def _parse_negative_match(raw: Any, path: str, schema_version: int) -> NegativeMatch:
    value = _object(raw, path, ("id", "when", "reason", "unknown_policy"), ("id", "when", "reason", "unknown_policy"))
    policy = value["unknown_policy"]
    if policy not in ("ignore", "block"):
        _fail(path + ".unknown_policy", "invalid-unknown-policy", "expected ignore or block")
    return NegativeMatch(
        _string(value["id"], path + ".id"),
        _parse_condition(value["when"], path + ".when", schema_version),
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
    if not is_canonical_https_url(url):
        _fail(path + ".url", "invalid-citation-url", "citation URLs must use canonical unambiguous https")
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


def _parse_example(raw: Any, path: str, schema_version: int) -> PinnedExample:
    common_fields = ("challenge_id", "event", "year", "repo_url", "repo_sha", "source_path", "source_lines", "inference_level")
    if schema_version == 1:
        value = _object(raw, path, common_fields, common_fields)
        source_kind = "remote"
    else:
        fields = common_fields + ("source_kind",)
        value = _object(raw, path, fields, fields)
        source_kind = value["source_kind"]
        if source_kind not in ("remote", "local"):
            _fail(path + ".source_kind", "invalid-source-kind", "expected remote or local")
    repo_url = value["repo_url"]
    repo_sha = value["repo_sha"]
    if source_kind == "remote":
        if not isinstance(repo_url, str) or not is_canonical_https_url(repo_url, repository=True):
            _fail(path + ".repo_url", "invalid-repository-url", "pinned repository URLs must use canonical unambiguous https")
        if not isinstance(repo_sha, str) or not GIT_SHA_RE.fullmatch(repo_sha):
            _fail(path + ".repo_sha", "invalid-repository-sha", "expected a 40-character lowercase commit SHA")
    elif repo_url is not None or repo_sha is not None:
        field = "repo_url" if repo_url is not None else "repo_sha"
        _fail(path + "." + field, "invalid-local-example", "local package examples may not claim a remote repository")
    source_lines = value["source_lines"]
    if not is_canonical_source_lines(source_lines):
        _fail(path + ".source_lines", "invalid-source-lines", "expected one canonical inclusive Lx-Ly range")
    level = value["inference_level"]
    levels = ("direct", "inferred") if schema_version == 1 else ("direct", "inferred", "variant")
    if level not in levels:
        _fail(path + ".inference_level", "invalid-inference-level", "expected {0}".format(", ".join(levels)))
    return PinnedExample(
        _string(value["challenge_id"], path + ".challenge_id"),
        _string(value["event"], path + ".event"),
        _integer(value["year"], path + ".year", 1),
        source_kind,
        repo_url,
        repo_sha,
        _parse_case_relative_path(value["source_path"], path + ".source_path", "invalid-source-path"),
        source_lines,
        level,
    )


def _parse_probe(raw: Any, path: str, schema_version: int) -> CheapProbe:
    value = _object(raw, path, ("id", "instruction", "max_seconds", "produces_facts"), ("id", "instruction", "max_seconds", "produces_facts"))
    fact_value_types = FACT_VALUE_TYPES_BY_SCHEMA[schema_version]
    produced = []
    for index, key in enumerate(_string_array(value["produces_facts"], path + ".produces_facts")):
        if key not in fact_value_types:
            _fail("{0}.produces_facts[{1}]".format(path, index), "unknown-fact-key", "fact key is not in schema version {0}".format(schema_version))
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
    fact_value_types = FACT_VALUE_TYPES_BY_SCHEMA[schema_version]
    parameter_signature = []
    for index, key in enumerate(_string_array(value["parameter_signature"], path + ".parameter_signature")):
        if key not in fact_value_types:
            _fail("{0}.parameter_signature[{1}]".format(path, index), "unknown-fact-key", "fact key is not in schema version {0}".format(schema_version))
        parameter_signature.append(FactKey(key))
    signals = tuple(_parse_signal(item, "{0}.signals[{1}]".format(path, index), schema_version) for index, item in enumerate(_array(value["signals"], path + ".signals")))
    _check_unique([item.id for item in signals], path + ".signals", "duplicate-signal-id")
    requires = tuple(_parse_rule(item, "{0}.requires[{1}]".format(path, index), schema_version) for index, item in enumerate(_array(value["requires"], path + ".requires")))
    rejects = tuple(_parse_rule(item, "{0}.rejects[{1}]".format(path, index), schema_version) for index, item in enumerate(_array(value["rejects"], path + ".rejects")))
    negative_matches = tuple(_parse_negative_match(item, "{0}.negative_matches[{1}]".format(path, index), schema_version) for index, item in enumerate(_array(value["negative_matches"], path + ".negative_matches")))
    _check_unique([item.id for item in requires], path + ".requires", "duplicate-rule-id")
    _check_unique([item.id for item in rejects], path + ".rejects", "duplicate-rule-id")
    _check_unique([item.id for item in negative_matches], path + ".negative_matches", "duplicate-negative-match-id")
    probes = tuple(_parse_probe(item, "{0}.cheap_probes[{1}]".format(path, index), schema_version) for index, item in enumerate(_array(value["cheap_probes"], path + ".cheap_probes")))
    procedure = tuple(_parse_procedure_step(item, "{0}.procedure[{1}]".format(path, index)) for index, item in enumerate(_array(value["procedure"], path + ".procedure")))
    citations = tuple(_parse_citation(item, "{0}.citations[{1}]".format(path, index)) for index, item in enumerate(_array(value["citations"], path + ".citations")))
    if not citations:
        _fail(path + ".citations", "missing-citation-identifier", "AttackCards require at least one citation")
    examples = tuple(_parse_example(item, "{0}.examples[{1}]".format(path, index), schema_version) for index, item in enumerate(_array(value["examples"], path + ".examples")))
    if card_id.startswith("paper.") and not examples:
        _fail(path + ".examples", "research-card-missing-pinned-example", "research-tier cards require a pinned example")
    verification = tuple(_parse_verification_step(item, "{0}.verification[{1}]".format(path, index)) for index, item in enumerate(_array(value["verification"], path + ".verification")))
    return AttackCard(
        schema_version=schema_version,
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
    if cards:
        catalog_version = cards[0].schema_version
        for index, card in enumerate(cards[1:], 1):
            if card.schema_version != catalog_version:
                _fail("$[{0}].schema_version".format(index), "mixed-schema-versions", "catalog cards must use one schema version")
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
