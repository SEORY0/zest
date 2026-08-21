#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Recover a bounded rotor conjugator and replay independent symbol mappings."""

from __future__ import annotations

import itertools
import json
import math
import sys
from pathlib import Path


MAX_INPUT_BYTES = 1_000_000


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


def _integer(document, key, minimum, maximum):
    if type(document) is not dict:
        raise SolverError("invalid-input")
    value = document.get(key)
    if type(value) is not int or value < minimum or value > maximum:
        raise SolverError("invalid-input")
    return value


def _permutation(value, size):
    if type(value) is not list or len(value) != size:
        raise SolverError("invalid-permutation")
    if any(type(item) is not int for item in value) or sorted(value) != list(range(size)):
        raise SolverError("invalid-permutation")
    return tuple(value)


def _inverse(permutation):
    result = [0] * len(permutation)
    for index, value in enumerate(permutation):
        result[value] = index
    return tuple(result)


def _compose(left, right):
    return tuple(left[right[index]] for index in range(len(left)))


def _conjugate(conjugator, source):
    return _compose(_compose(conjugator, source), _inverse(conjugator))


def _parse_training(document, size):
    raw_training = document.get("training")
    if type(raw_training) is not list or not raw_training or len(raw_training) > 16:
        raise SolverError("invalid-input")
    training = []
    for equation in raw_training:
        if type(equation) is not dict:
            raise SolverError("invalid-input")
        training.append((_permutation(equation.get("source"), size), _permutation(equation.get("target"), size)))
    return tuple(training)


def _parse_replay(document, size):
    raw_replay = document.get("replay")
    if type(raw_replay) is not list or not raw_replay or len(raw_replay) > 64:
        raise SolverError("invalid-input")
    replay = []
    for mapping in raw_replay:
        replay.append(
            (
                _integer(mapping, "input", 0, size - 1),
                _integer(mapping, "output", 0, size - 1),
            )
        )
    return tuple(replay)


def _solve(document):
    size = _integer(document, "size", 2, 8)
    max_permutations = _integer(document, "max_permutations", 1, 100_000)
    if math.factorial(size) > max_permutations:
        raise SolverError("work-bound-exceeded")
    training = _parse_training(document, size)
    replay = _parse_replay(document, size)
    matches = []
    for candidate in itertools.permutations(range(size)):
        if all(_conjugate(candidate, source) == target for source, target in training):
            matches.append(candidate)
            if len(matches) > 1:
                raise SolverError("ambiguous-solution")
    if not matches:
        raise SolverError("no-solution")
    permutation = matches[0]
    if not all(permutation[source] == target for source, target in replay):
        raise SolverError("proof-mismatch")
    if not all(_conjugate(permutation, source) == target for source, target in training):
        raise SolverError("proof-mismatch")
    return {
        "construction": "rotor-group-conjugacy",
        "permutation": list(permutation),
        "proof": {"conjugacy_equations": len(training), "replay_mappings": len(replay)},
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
