#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Rank a validated fingerprint against a validated local AttackCard catalog."""

import json
import math
import sys
from pathlib import Path
from typing import Dict, Sequence

from zest_crypto_conditions import rank_cards
from zest_crypto_parse import parse_catalog, parse_fingerprint, validate_catalog
from zest_crypto_types import CatalogIssue, JsonValue, ParseError


def _write(document: Dict[str, JsonValue]) -> None:
    sys.stdout.write(json.dumps(document, sort_keys=True, indent=2) + "\n")


def _failure(issue: CatalogIssue) -> int:
    _write({"ok": False, "issues": [{"path": issue.path, "code": issue.code}]})
    return 2


def _reject_non_standard_json_constant(value: str) -> None:
    raise json.JSONDecodeError("non-standard JSON constant: {0}".format(value), value, 0)


def _parse_finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise json.JSONDecodeError("non-finite JSON number: {0}".format(value), value, 0)
    return number


def _parse_json_integer(value: str) -> int:
    try:
        return int(value)
    except ValueError as error:
        raise json.JSONDecodeError("invalid JSON integer", value, 0) from error


def _read_json(path: Path) -> JsonValue:
    contents = path.read_text(encoding="utf-8")
    return json.loads(contents, parse_constant=_reject_non_standard_json_constant, parse_float=_parse_finite_json_float, parse_int=_parse_json_integer)


def main(arguments: Sequence[str]) -> int:
    if len(arguments) != 2:
        return _failure(CatalogIssue("$", "invalid-arguments", "expected fingerprint and AttackCards JSON paths"))
    fingerprint_path = Path(arguments[0])
    catalog_path = Path(arguments[1])
    try:
        raw_fingerprint = _read_json(fingerprint_path)
        raw_catalog = _read_json(catalog_path)
    except OSError as error:
        return _failure(CatalogIssue("$", "input-unreadable", str(error)))
    except UnicodeError as error:
        return _failure(CatalogIssue("$", "input-undecodable", str(error)))
    except RecursionError as error:
        return _failure(CatalogIssue("$", "input-too-deep", str(error)))
    except json.JSONDecodeError as error:
        return _failure(CatalogIssue("$", "invalid-json", "line {0}, column {1}".format(error.lineno, error.colno)))
    except OverflowError as error:
        return _failure(CatalogIssue("$", "invalid-json", str(error)))
    try:
        fingerprint = parse_fingerprint(raw_fingerprint)
        cards = parse_catalog(raw_catalog)
        issues = validate_catalog(cards, Path(__file__).resolve().parents[1])
    except ParseError as error:
        return _failure(CatalogIssue(error.path, error.code, error.detail))
    if issues:
        return _failure(issues[0])
    _write(rank_cards(fingerprint, cards).to_document())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
