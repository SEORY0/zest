#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Validate a decoded AttackCard catalog at the single JSON input boundary."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

from zest_crypto_parse import parse_catalog, validate_catalog
from zest_crypto_types import CatalogIssue, ParseError


def _issue_document(issue: CatalogIssue) -> Dict[str, str]:
    """Keep the public issue envelope stable and free of host-specific details."""

    return {"path": issue.path, "code": issue.code}


def _write(document: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(document, sort_keys=True, indent=2) + "\n")


def _failure(issue: CatalogIssue) -> int:
    _write({"ok": False, "issues": [_issue_document(issue)]})
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


def main(arguments: Sequence[str]) -> int:
    if len(arguments) != 1:
        return _failure(CatalogIssue("$", "invalid-arguments", "expected one AttackCards JSON path"))
    catalog_path = Path(arguments[0])
    try:
        contents = catalog_path.read_text(encoding="utf-8")
    except OSError as error:
        return _failure(CatalogIssue("$", "input-unreadable", str(error)))
    except UnicodeError as error:
        return _failure(CatalogIssue("$", "input-undecodable", str(error)))
    try:
        raw = json.loads(
            contents,
            parse_constant=_reject_non_standard_json_constant,
            parse_float=_parse_finite_json_float,
            parse_int=_parse_json_integer,
        )
    except RecursionError as error:
        return _failure(CatalogIssue("$", "input-too-deep", str(error)))
    except json.JSONDecodeError as error:
        return _failure(CatalogIssue("$", "invalid-json", "line {0}, column {1}".format(error.lineno, error.colno)))
    except OverflowError as error:
        return _failure(CatalogIssue("$", "invalid-json", str(error)))
    try:
        cards = parse_catalog(raw)
    except ParseError as error:
        return _failure(CatalogIssue(error.path, error.code, error.detail))
    try:
        issues = validate_catalog(cards, Path(__file__).resolve().parents[1])
    except ParseError as error:
        return _failure(CatalogIssue(error.path, error.code, error.detail))
    if issues:
        _write({"ok": False, "issues": [_issue_document(issue) for issue in issues]})
        return 2
    _write({"ok": True, "card_count": len(cards), "issues": []})
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
