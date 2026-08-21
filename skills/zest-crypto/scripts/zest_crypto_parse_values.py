# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Shared schema constants and value helpers for Zest crypto parsing."""

from __future__ import annotations

import math
import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

from zest_crypto_types import FactValue, ParseError


SCHEMA_VERSION = 2
READ_ONLY_SCHEMA_VERSIONS = frozenset((1,))
SUPPORTED_SCHEMA_VERSIONS = READ_ONLY_SCHEMA_VERSIONS | frozenset((SCHEMA_VERSION,))
CANONICAL_PROVENANCE_SCHEMA_VERSIONS = SUPPORTED_SCHEMA_VERSIONS

V1_FACT_VALUE_TYPES: Dict[str, str] = {
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
V2_FACT_VALUE_TYPES: Dict[str, str] = {
    "signature.nonce_leak_orientation": "string",
    "signature.hnp_model": "string",
    "signature.hnp_parameter_bound_verified": "boolean",
    "signature.nonce_projection_bound_verified": "boolean",
    "oracle.recovery_bytes": "integer",
    "construction.exploit_invariant_verified": "boolean",
}
FACT_VALUE_TYPES = {**V1_FACT_VALUE_TYPES, **V2_FACT_VALUE_TYPES}
FACT_VALUE_TYPES_BY_SCHEMA = {
    1: V1_FACT_VALUE_TYPES,
    2: FACT_VALUE_TYPES,
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
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        _fail(path, "unknown-schema-version", "supported schema versions are 1 and 2")
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
