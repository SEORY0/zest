#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Solve a bounded four-list generalized-birthday toy instance exactly."""

from __future__ import annotations

import json
import sys
from pathlib import Path


MAX_INPUT_BYTES = 1_000_000
MAX_INTEGER_BITS = 4096


class SolverError(Exception):
    def __init__(self, code):
        self.code = code


def _emit(document):
    sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")


def _failure(code):
    _emit({"error": {"code": code}, "verified": False})
    return 2


def _reject_constant(_value):
    raise SolverError("invalid-json")


def _load(path):
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise SolverError("input-too-large")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise SolverError("input-unreadable")
    try:
        document = json.loads(text, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError):
        raise SolverError("invalid-json")
    if type(document) is not dict:
        raise SolverError("invalid-input")
    return document


def _integer(value, minimum):
    if type(value) is not int or value < minimum or value.bit_length() > MAX_INTEGER_BITS:
        raise SolverError("invalid-input")
    return value


def _parse_lists(document, modulus):
    raw_lists = document.get("lists")
    if type(raw_lists) is not list or len(raw_lists) != 4:
        raise SolverError("invalid-input")
    parsed = []
    for raw_list in raw_lists:
        if type(raw_list) is not list or not raw_list or len(raw_list) > 256:
            raise SolverError("invalid-input")
        values = tuple(_integer(value, 0) for value in raw_list)
        if any(value >= modulus for value in values):
            raise SolverError("invalid-input")
        parsed.append(values)
    return tuple(parsed)


def _solve(document):
    modulus = _integer(document.get("modulus"), 2)
    target = _integer(document.get("target"), 0)
    max_pair_sums = _integer(document.get("max_pair_sums"), 1)
    if target >= modulus or max_pair_sums > 1_000_000:
        raise SolverError("invalid-input")
    lists = _parse_lists(document, modulus)
    if len(lists[0]) * len(lists[1]) > max_pair_sums or len(lists[2]) * len(lists[3]) > max_pair_sums:
        raise SolverError("work-bound-exceeded")
    left_pairs = {}
    for first_index, first_value in enumerate(lists[0]):
        for second_index, second_value in enumerate(lists[1]):
            residue = (first_value + second_value) % modulus
            if residue not in left_pairs:
                left_pairs[residue] = (first_index, second_index)
    solution = None
    for third_index, third_value in enumerate(lists[2]):
        for fourth_index, fourth_value in enumerate(lists[3]):
            needed = (target - third_value - fourth_value) % modulus
            if needed in left_pairs:
                solution = left_pairs[needed] + (third_index, fourth_index)
                break
        if solution is not None:
            break
    if solution is None:
        raise SolverError("no-solution")
    values = [lists[index][item_index] for index, item_index in enumerate(solution)]
    exact_sum = sum(values)
    residue = exact_sum % modulus
    if residue != target:
        raise SolverError("proof-mismatch")
    return {
        "construction": "wagner-four-list-exact-sum",
        "indices": list(solution),
        "proof": {"residue": residue, "sum": exact_sum},
        "values": values,
        "verified": True,
    }


def main(arguments):
    if len(arguments) != 1:
        return _failure("invalid-arguments")
    try:
        result = _solve(_load(Path(arguments[0])))
    except SolverError as error:
        return _failure(error.code)
    _emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
