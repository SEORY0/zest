#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Rank a validated fingerprint against a validated local AttackCard catalog."""

import json
import sys
from pathlib import Path
from typing import Dict, Sequence

from zest_crypto_conditions import canonical_digest, rank_cards_with_digests
from zest_crypto_input import InputBoundaryError, loads_bounded_json, read_bounded_text
from zest_crypto_parse import parse_catalog, parse_fingerprint, validate_catalog
from zest_crypto_types import CatalogIssue, JsonValue, ParseError


def _write(document: Dict[str, JsonValue]) -> None:
    sys.stdout.write(json.dumps(document, sort_keys=True, indent=2) + "\n")


def _failure(issue: CatalogIssue) -> int:
    _write({"ok": False, "issues": [{"path": issue.path, "code": issue.code}]})
    return 2


def _read_json(path: Path) -> JsonValue:
    return loads_bounded_json(read_bounded_text(str(path), "$"))


def main(arguments: Sequence[str]) -> int:
    if len(arguments) != 2:
        return _failure(CatalogIssue("$", "invalid-arguments", "expected fingerprint and AttackCards JSON paths"))
    fingerprint_path = Path(arguments[0])
    catalog_path = Path(arguments[1])
    try:
        raw_fingerprint = _read_json(fingerprint_path)
        raw_catalog = _read_json(catalog_path)
    except InputBoundaryError as error:
        return _failure(CatalogIssue(error.path, error.code))
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
        if not issues:
            report = rank_cards_with_digests(
                fingerprint,
                cards,
                canonical_digest(raw_fingerprint),
                canonical_digest(raw_catalog),
            )
    except ParseError as error:
        return _failure(CatalogIssue(error.path, error.code, error.detail))
    if issues:
        return _failure(issues[0])
    _write(report.to_document())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
