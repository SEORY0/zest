# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Construct deterministic Zest crypto documents and digests."""

from hashlib import sha256
import json
from typing import Dict, Tuple

from zest_crypto_parse_values import FACT_VALUE_TYPES_BY_SCHEMA
from zest_crypto_types import AttackCard, Condition, Fact, Fingerprint, JsonValue, Operator


def canonical_digest(document: JsonValue) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def _fingerprint_document(fingerprint: Fingerprint) -> Dict[str, JsonValue]:
    return {
        "schema_version": fingerprint.schema_version, "case_id": fingerprint.case_id,
        "inputs": [{"id": item.id, "path": item.path, "sha256": item.sha256, "media_type": item.media_type} for item in fingerprint.inputs], "facts": [_fact_document(fact, fingerprint.schema_version) for fact in fingerprint.facts],
        "capabilities": [{"command": item.command, "available": item.available, "version": item.version} for item in fingerprint.capabilities],
        "constraints": {"network": fingerprint.constraints.network, "oracle_access": fingerprint.constraints.oracle_access, "max_seconds": fingerprint.constraints.max_seconds, "max_memory_mb": fingerprint.constraints.max_memory_mb, "max_oracle_queries": fingerprint.constraints.max_oracle_queries},
    }


def _fact_document(fact: Fact, schema_version: int) -> Dict[str, JsonValue]:
    evidence: Dict[str, JsonValue] = {key: value for key, value in (("input_id", fact.evidence.input_id), ("locator", fact.evidence.locator), ("source_fact_ids", list(fact.evidence.source_fact_ids) if fact.evidence.source_fact_ids else None), ("rationale", fact.evidence.rationale)) if value is not None}
    value = list(fact.value) if isinstance(fact.value, tuple) else fact.value
    return {"id": str(fact.id), "key": str(fact.key), "value": value, "value_type": FACT_VALUE_TYPES_BY_SCHEMA[schema_version][str(fact.key)], "status": fact.status.value, "evidence": evidence}


def _catalog_document(cards: Tuple[AttackCard, ...]) -> Tuple[Dict[str, JsonValue], ...]:
    return tuple(_card_document(card) for card in cards)


def _card_document(card: AttackCard) -> Dict[str, JsonValue]:
    return {
        "schema_version": card.schema_version, "id": str(card.id), "version": card.version, "title": card.title, "canonical_family_id": card.canonical_family_id,
        "family_aliases": list(card.family_aliases), "summary": card.summary, "parameter_signature": list(card.parameter_signature),
        "signals": [{"id": item.id, "when": _condition_document(item.when), "weight": item.weight, "reason": item.reason} for item in card.signals],
        "requires": [{"id": item.id, "when": _condition_document(item.when), "reason": item.reason} for item in card.requires],
        "rejects": [{"id": item.id, "when": _condition_document(item.when), "reason": item.reason} for item in card.rejects],
        "negative_matches": [{"id": item.id, "when": _condition_document(item.when), "reason": item.reason, "unknown_policy": item.unknown_policy} for item in card.negative_matches],
        "cheap_probes": [{"id": item.id, "instruction": item.instruction, "max_seconds": item.max_seconds, "produces_facts": list(item.produces_facts)} for item in card.cheap_probes],
        "expected_cost": {"class": card.expected_cost.cost_class.value, "notes": card.expected_cost.notes},
        "tooling": [{"command": item.command, "required": item.required, "packages": list(item.packages), "reason": item.reason} for item in card.tooling],
        "template": card.template, "procedure": [{"id": item.id, "instruction": item.instruction} for item in card.procedure],
        "citations": [{"kind": item.kind, "paper_id": item.paper_id, "title": item.title, "url": item.url, "year": item.year, "section": item.section, "assumptions": list(item.assumptions), "verified_on": item.verified_on} for item in card.citations],
        "examples": [_example_document(item, card.schema_version) for item in card.examples],
        "verification": [{"kind": item.kind, "instruction": item.instruction} for item in card.verification],
    }


def _example_document(item, schema_version: int) -> Dict[str, JsonValue]:
    document = {"challenge_id": item.challenge_id, "event": item.event, "year": item.year, "repo_url": item.repo_url, "repo_sha": item.repo_sha, "source_path": item.source_path, "source_lines": item.source_lines, "inference_level": item.inference_level}
    if schema_version == 2:
        document["source_kind"] = item.source_kind
    return document


def _condition_document(condition: Condition) -> Dict[str, JsonValue]:
    if condition.fact is not None:
        document: Dict[str, JsonValue] = {"fact": str(condition.fact), "op": condition.op.value if condition.op is not None else None}
        if condition.op is not Operator.EXISTS:
            document["value"] = list(condition.value) if isinstance(condition.value, tuple) else condition.value
        return document
    if condition.all_of:
        return {"all": [_condition_document(item) for item in condition.all_of]}
    if condition.any_of:
        return {"any": [_condition_document(item) for item in condition.any_of]}
    if condition.not_ is not None:
        return {"not": _condition_document(condition.not_)}
    raise AssertionError("parsed condition has no predicate or boolean group")
