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
import os
import stat
import sys
from pathlib import Path


MAX_INPUT_BYTES = 1_000_000
MAX_JSON_DEPTH = 32
MAX_JSON_INTEGER_DIGITS = 4096


class SolverError(Exception):
    def __init__(self, code):
        self.code = code


def _emit(document):
    sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")


def _failure(code):
    _emit({"error": {"code": code}, "verified": False})
    return 2


def _reject_constant(_value):
    raise ValueError


def _parse_json_integer(token):
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError
    value = 0
    for character in digits:
        value = value * 10 + ord(character) - ord("0")
    return -value if token.startswith("-") else value


def _parse_json_float(token):
    if len(token) > 128:
        raise ValueError
    value = float(token)
    if not math.isfinite(value):
        raise ValueError
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _check_depth(document):
    pending = [(document, 1)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise SolverError("invalid-json")
        if type(value) is dict:
            pending.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            pending.extend((item, depth + 1) for item in value)


def _read_regular(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise SolverError("input-unreadable")
        handle = os.fdopen(descriptor, "rb")
        descriptor = -1
        with handle:
            content = handle.read(MAX_INPUT_BYTES + 1)
    except SolverError:
        raise
    except (OSError, MemoryError):
        raise SolverError("input-unreadable")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > MAX_INPUT_BYTES:
        raise SolverError("input-too-large")
    try:
        return content.decode("utf-8")
    except (UnicodeError, MemoryError):
        raise SolverError("input-unreadable")


def _load(path):
    try:
        document = json.loads(
            _read_regular(path),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_parse_json_float,
            parse_int=_parse_json_integer,
        )
    except (ValueError, RecursionError, MemoryError):
        raise SolverError("invalid-json")
    if type(document) is not dict:
        raise SolverError("invalid-input")
    _check_depth(document)
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
    seen_inputs = set()
    for mapping in raw_replay:
        source = _integer(mapping, "input", 0, size - 1)
        target = _integer(mapping, "output", 0, size - 1)
        if source in seen_inputs:
            raise SolverError("duplicate-replay-input")
        seen_inputs.add(source)
        replay.append((source, target))
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
