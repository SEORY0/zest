# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Evaluate AttackCard conditions and construct deterministic rank reports."""

from dataclasses import dataclass, replace
from hashlib import sha256
import json
from operator import ge, gt, le, lt
from typing import Callable, Dict, Iterable, Optional, Sequence, Tuple, Union

from zest_crypto_parse import FACT_VALUE_TYPES
from zest_crypto_types import (
    AttackCard,
    Capability,
    CardId,
    CardState,
    Condition,
    CostClass,
    Fact,
    FactIndex,
    FactStatus,
    FactValue,
    Fingerprint,
    JsonValue,
    NegativeMatch,
    Operator,
    Rule,
    Truth,
)


Predicate = Callable[[FactValue, Optional[FactValue]], bool]
Gate = Union[Rule, NegativeMatch]
COST_PENALTIES: Dict[CostClass, int] = {CostClass.LOW: 0, CostClass.MEDIUM: 10, CostClass.HIGH: 25, CostClass.ORACLE_BOUND: 15}


@dataclass(frozen=True)
class CardEvaluation:
    card_id: CardId
    state: CardState
    score: Optional[int]
    matched_signals: Tuple[str, ...]
    unmatched_signals: Tuple[str, ...]
    evidence_fact_ids: Tuple[str, ...]
    required_tools: Tuple[str, ...]
    rule_id: Optional[str]
    reason: Optional[str]


@dataclass(frozen=True)
class RankReport:
    schema_version: int
    fingerprint_sha256: str
    catalog_sha256: str
    eligible: Tuple[CardEvaluation, ...]
    blocked: Tuple[CardEvaluation, ...]
    rejected: Tuple[CardEvaluation, ...]

    def to_document(self) -> Dict[str, JsonValue]:
        return {"schema_version": self.schema_version, "fingerprint_sha256": self.fingerprint_sha256, "catalog_sha256": self.catalog_sha256, "eligible": [_eligible_document(item) for item in self.eligible], "blocked": [_non_eligible_document(item) for item in self.blocked], "rejected": [_non_eligible_document(item) for item in self.rejected]}


def _predicate_exists(_actual: FactValue, _expected: Optional[FactValue]) -> bool:
    return True


def _predicate_eq(actual: FactValue, expected: Optional[FactValue]) -> bool:
    return actual == expected


def _predicate_neq(actual: FactValue, expected: Optional[FactValue]) -> bool:
    return actual != expected


def _predicate_in(actual: FactValue, expected: Optional[FactValue]) -> bool:
    if not isinstance(expected, tuple):
        return False
    if isinstance(actual, tuple):
        return any(item in expected for item in actual)
    return actual in expected


def _predicate_contains(actual: FactValue, expected: Optional[FactValue]) -> bool:
    if isinstance(actual, str):
        return isinstance(expected, str) and expected in actual
    if isinstance(actual, tuple):
        return expected in actual
    return False


def _predicate_len_eq(actual: FactValue, expected: Optional[FactValue]) -> bool:
    return _non_boolean_integer(expected) and _value_length(actual) == expected


def _predicate_len_gte(actual: FactValue, expected: Optional[FactValue]) -> bool:
    return _non_boolean_integer(expected) and _value_length(actual) >= expected


def _non_boolean_integer(value: Optional[FactValue]) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _value_length(value: FactValue) -> int:
    if isinstance(value, (str, tuple)):
        return len(value)
    raise AssertionError("parsed length predicates contain strings or tuples")


PREDICATES: Dict[Operator, Predicate] = {
    Operator.EXISTS: _predicate_exists,
    Operator.EQ: _predicate_eq,
    Operator.NEQ: _predicate_neq,
    Operator.LT: lt,
    Operator.LTE: le,
    Operator.GT: gt,
    Operator.GTE: ge,
    Operator.IN: _predicate_in,
    Operator.CONTAINS: _predicate_contains,
    Operator.LEN_EQ: _predicate_len_eq,
    Operator.LEN_GTE: _predicate_len_gte,
}


def evaluate_condition(condition: Condition, facts: FactIndex, hard: bool) -> Truth:
    if condition.fact is not None:
        return _evaluate_predicate(condition, facts, hard)
    if condition.all_of:
        return _truth_all(evaluate_condition(item, facts, hard) for item in condition.all_of)
    if condition.any_of:
        return _truth_any(evaluate_condition(item, facts, hard) for item in condition.any_of)
    if condition.not_ is not None:
        return _truth_not(evaluate_condition(condition.not_, facts, hard))
    raise AssertionError("parsed condition has no predicate or boolean group")


def _evaluate_predicate(condition: Condition, facts: FactIndex, hard: bool) -> Truth:
    fact = facts.get(condition.fact)
    if fact is None:
        return {Operator.EXISTS: Truth.FALSE}.get(condition.op, Truth.UNKNOWN)
    if hard and fact.status is FactStatus.INFERRED:
        return Truth.UNKNOWN
    if condition.op is None:
        raise AssertionError("parsed predicate has no operator")
    matched = PREDICATES[condition.op](fact.value, condition.value)
    return Truth.TRUE if matched else Truth.FALSE


def _truth_all(values: Iterable[Truth]) -> Truth:
    values_tuple = tuple(values)
    if Truth.FALSE in values_tuple:
        return Truth.FALSE
    if Truth.UNKNOWN in values_tuple:
        return Truth.UNKNOWN
    return Truth.TRUE


def _truth_any(values: Iterable[Truth]) -> Truth:
    values_tuple = tuple(values)
    if Truth.TRUE in values_tuple:
        return Truth.TRUE
    if Truth.UNKNOWN in values_tuple:
        return Truth.UNKNOWN
    return Truth.FALSE


def _truth_not(value: Truth) -> Truth:
    mapping = {Truth.TRUE: Truth.FALSE, Truth.FALSE: Truth.TRUE, Truth.UNKNOWN: Truth.UNKNOWN}
    return mapping[value]


def classify_card(card: AttackCard, facts: FactIndex) -> CardEvaluation:
    matched_reject = _first_gate_with_truth(card.rejects, facts, Truth.TRUE)
    if matched_reject is not None:
        return _gate_evaluation(card.id, CardState.REJECTED, matched_reject, facts)
    matched_negative = _first_gate_with_truth(card.negative_matches, facts, Truth.TRUE)
    if matched_negative is not None:
        return _gate_evaluation(card.id, CardState.REJECTED, matched_negative, facts)
    false_requirement = _first_gate_with_truth(card.requires, facts, Truth.FALSE)
    if false_requirement is not None:
        return _gate_evaluation(card.id, CardState.REJECTED, false_requirement, facts)
    blocking_negative = _first_blocking_negative(card.negative_matches, facts)
    if blocking_negative is not None:
        return _gate_evaluation(card.id, CardState.BLOCKED, blocking_negative, facts)
    unknown_requirement = _first_gate_with_truth(card.requires, facts, Truth.UNKNOWN)
    if unknown_requirement is not None:
        return _gate_evaluation(card.id, CardState.BLOCKED, unknown_requirement, facts)
    return CardEvaluation(card.id, CardState.ELIGIBLE, None, (), (), (), (), None, None)


def _first_gate_with_truth(gates: Sequence[Gate], facts: FactIndex, wanted: Truth) -> Optional[Gate]:
    for gate in gates:
        if evaluate_condition(gate.when, facts, True) is wanted:
            return gate
    return None


def _first_blocking_negative(matches: Sequence[NegativeMatch], facts: FactIndex) -> Optional[NegativeMatch]:
    for match in matches:
        if match.unknown_policy == "block" and evaluate_condition(match.when, facts, True) is Truth.UNKNOWN:
            return match
    return None


def _gate_evaluation(card_id: CardId, state: CardState, gate: Gate, facts: FactIndex) -> CardEvaluation:
    return CardEvaluation(card_id, state, None, (), (), _condition_evidence(gate.when, facts), (), gate.id, gate.reason)


def _condition_evidence(condition: Condition, facts: FactIndex) -> Tuple[str, ...]:
    if condition.fact is not None:
        fact = facts.get(condition.fact)
        if fact is None or fact.status is FactStatus.INFERRED:
            return ()
        return (str(fact.id),)
    children = condition.all_of or condition.any_of
    if children:
        return _unique_fact_ids(_condition_evidence(item, facts) for item in children)
    if condition.not_ is not None:
        return _condition_evidence(condition.not_, facts)
    raise AssertionError("parsed condition has no predicate or boolean group")


def _unique_fact_ids(groups: Iterable[Tuple[str, ...]]) -> Tuple[str, ...]:
    return tuple(dict.fromkeys(item for group in groups for item in group))


def rank_cards(fingerprint: Fingerprint, cards: Tuple[AttackCard, ...]) -> RankReport:
    return _rank_cards(fingerprint, cards, canonical_digest(_fingerprint_document(fingerprint)), canonical_digest(_catalog_document(cards)))


def rank_cards_with_digests(fingerprint: Fingerprint, cards: Tuple[AttackCard, ...], fingerprint_sha256: str, catalog_sha256: str) -> RankReport:
    return _rank_cards(fingerprint, cards, fingerprint_sha256, catalog_sha256)


def _rank_cards(fingerprint: Fingerprint, cards: Tuple[AttackCard, ...], fingerprint_sha256: str, catalog_sha256: str) -> RankReport:
    facts = {fact.key: fact for fact in fingerprint.facts}
    budget = facts.get("oracle.query_budget")
    limit = fingerprint.constraints.max_oracle_queries
    if budget is not None and limit is not None and isinstance(budget.value, int) and not isinstance(budget.value, bool):
        facts[budget.key] = replace(budget, value=min(budget.value, limit))
    capabilities = {capability.command: capability for capability in fingerprint.capabilities}
    evaluations = tuple(_rank_card(card, facts, capabilities) for card in cards)
    eligible = tuple(sorted((item for item in evaluations if item.state is CardState.ELIGIBLE), key=lambda item: (-_required_score(item), str(item.card_id))))
    blocked = tuple(sorted((item for item in evaluations if item.state is CardState.BLOCKED), key=lambda item: str(item.card_id)))
    rejected = tuple(sorted((item for item in evaluations if item.state is CardState.REJECTED), key=lambda item: str(item.card_id)))
    return RankReport(1, fingerprint_sha256, catalog_sha256, eligible, blocked, rejected)


def _rank_card(card: AttackCard, facts: FactIndex, capabilities: Dict[str, Capability]) -> CardEvaluation:
    classification = classify_card(card, facts)
    if classification.state is not CardState.ELIGIBLE:
        return classification
    missing_tool = next((tool for tool in card.tooling if tool.required and (tool.command not in capabilities or not capabilities[tool.command].available)), None)
    if missing_tool is not None:
        return CardEvaluation(card.id, CardState.BLOCKED, None, (), (), (), (), "tool:{0}".format(missing_tool.command), missing_tool.reason)
    matched_signals = tuple(signal for signal in card.signals if evaluate_condition(signal.when, facts, False) is Truth.TRUE)
    unmatched_signals = tuple(signal.id for signal in card.signals if signal not in matched_signals)
    evidence = _unique_fact_ids(_condition_evidence(signal.when, facts) for signal in matched_signals)
    score = sum(signal.weight for signal in matched_signals) - COST_PENALTIES[card.expected_cost.cost_class]
    required_tools = tuple(tool.command for tool in card.tooling if tool.required)
    return CardEvaluation(card.id, CardState.ELIGIBLE, score, tuple(signal.id for signal in matched_signals), unmatched_signals, evidence, required_tools, None, None)


def _required_score(evaluation: CardEvaluation) -> int:
    if evaluation.score is None:
        raise AssertionError("eligible rankings always have a score")
    return evaluation.score


def _eligible_document(item: CardEvaluation) -> Dict[str, JsonValue]:
    return {"card_id": str(item.card_id), "score": _required_score(item), "matched_signals": list(item.matched_signals), "unmatched_signals": list(item.unmatched_signals), "evidence_fact_ids": list(item.evidence_fact_ids), "required_tools": list(item.required_tools)}


def _non_eligible_document(item: CardEvaluation) -> Dict[str, JsonValue]:
    if item.rule_id is None or item.reason is None:
        raise AssertionError("blocked and rejected evaluations always have a rule")
    return {"card_id": str(item.card_id), "rule_id": item.rule_id, "reason": item.reason, "evidence_fact_ids": list(item.evidence_fact_ids)}


def canonical_digest(document: JsonValue) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def _fingerprint_document(fingerprint: Fingerprint) -> Dict[str, JsonValue]:
    return {
        "schema_version": fingerprint.schema_version, "case_id": fingerprint.case_id,
        "inputs": [{"id": item.id, "path": item.path, "sha256": item.sha256, "media_type": item.media_type} for item in fingerprint.inputs], "facts": [_fact_document(fact) for fact in fingerprint.facts],
        "capabilities": [{"command": item.command, "available": item.available, "version": item.version} for item in fingerprint.capabilities],
        "constraints": {"network": fingerprint.constraints.network, "max_seconds": fingerprint.constraints.max_seconds, "max_memory_mb": fingerprint.constraints.max_memory_mb, "max_oracle_queries": fingerprint.constraints.max_oracle_queries},
    }


def _fact_document(fact: Fact) -> Dict[str, JsonValue]:
    evidence: Dict[str, JsonValue] = {key: value for key, value in (("input_id", fact.evidence.input_id), ("locator", fact.evidence.locator), ("source_fact_ids", list(fact.evidence.source_fact_ids) if fact.evidence.source_fact_ids else None), ("rationale", fact.evidence.rationale)) if value is not None}
    value = list(fact.value) if isinstance(fact.value, tuple) else fact.value
    return {"id": str(fact.id), "key": str(fact.key), "value": value, "value_type": FACT_VALUE_TYPES[str(fact.key)], "status": fact.status.value, "evidence": evidence}


def _catalog_document(cards: Tuple[AttackCard, ...]) -> Tuple[Dict[str, JsonValue], ...]:
    return tuple(_card_document(card) for card in cards)


def _card_document(card: AttackCard) -> Dict[str, JsonValue]:
    return {
        "schema_version": 1, "id": str(card.id), "version": card.version, "title": card.title, "canonical_family_id": card.canonical_family_id,
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
        "examples": [{"challenge_id": item.challenge_id, "event": item.event, "year": item.year, "source_kind": item.source_kind, "repo_url": item.repo_url, "repo_sha": item.repo_sha, "source_path": item.source_path, "source_lines": item.source_lines, "inference_level": item.inference_level} for item in card.examples],
        "verification": [{"kind": item.kind, "instruction": item.instruction} for item in card.verification],
    }


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
