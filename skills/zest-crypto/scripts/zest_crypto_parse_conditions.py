# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Condition, rule, signal, and negative-match parsing for Zest crypto."""

from __future__ import annotations

from typing import Any

from zest_crypto_types import (
    Condition,
    FactKey,
    FactValue,
    NegativeMatch,
    Operator,
    Rule,
    Signal,
)
from zest_crypto_parse_values import (
    CONTAINS_VALUE_TYPES,
    FACT_VALUE_TYPES_BY_SCHEMA,
    LENGTH_VALUE_TYPES,
    NUMERIC_VALUE_TYPES,
    _array,
    _fail,
    _integer,
    _object,
    _parse_fact_value,
    _string,
)


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
