#!/usr/bin/env sage
"""Run a bounded monic univariate Coppersmith instance and verify every root."""

import json
import math
import os
import stat
import sys
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

MAX_INPUT_BYTES = 1_000_000
MAX_INTEGER_BITS = 16_384
MAX_DEGREE = 16
MAX_JSON_DEPTH = 32
MAX_JSON_INTEGER_DIGITS = 4096
MAX_BETA_DENOMINATOR = 64


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
    value = int()
    ten = int("10")
    zero_code = ord("0")
    for character in digits:
        value = value * ten + ord(character) - zero_code
    return -value if token.startswith("-") else value


def _parse_json_float(token):
    if len(token) > 128:
        raise ValueError
    value = Decimal(token)
    if not value.is_finite() or abs(value.as_tuple().exponent) > 128:
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


def _integer(document, key, minimum):
    value = document.get(key)
    if type(value) is not int or value < minimum or value.bit_length() > MAX_INTEGER_BITS:
        raise SolverError("invalid-input")
    return value


def _parse(document):
    modulus = _integer(document, "modulus", 3)
    bound = _integer(document, "bound", 1)
    max_roots = _integer(document, "max_roots", 1)
    beta_value = document.get("beta")
    coefficients = document.get("coefficients")
    if type(beta_value) not in (int, Decimal) or type(beta_value) is bool:
        raise SolverError("invalid-beta")
    if type(beta_value) is Decimal and abs(beta_value.as_tuple().exponent) > MAX_BETA_DENOMINATOR:
        raise SolverError("invalid-beta")
    beta = Fraction(beta_value)
    if beta <= 0 or beta > 1 or beta.denominator > MAX_BETA_DENOMINATOR:
        raise SolverError("invalid-beta")
    if bound >= modulus or bound.bit_length() > MAX_INTEGER_BITS or max_roots > 1024:
        raise SolverError("invalid-bound")
    if type(coefficients) is not list or len(coefficients) < 2 or len(coefficients) > MAX_DEGREE + 1:
        raise SolverError("invalid-input")
    if any(type(value) is not int or value.bit_length() > MAX_INTEGER_BITS for value in coefficients):
        raise SolverError("invalid-input")
    if coefficients[-1] % modulus != 1:
        raise SolverError("polynomial-not-monic")
    return modulus, tuple(coefficients), bound, beta, max_roots


def _evaluate(coefficients, value):
    result = 0
    for coefficient in reversed(coefficients):
        result = result * value + coefficient
    return result


def _solve(document):
    modulus, coefficients, bound, beta, max_roots = _parse(document)
    from sage.all import PolynomialRing, Zmod

    ring = PolynomialRing(Zmod(modulus), "x")
    variable = ring.gen()
    polynomial = ring(0)
    for exponent, coefficient in enumerate(coefficients):
        polynomial += Zmod(modulus)(coefficient) * variable ** exponent
    if not polynomial.is_monic():
        raise SolverError("polynomial-not-monic")
    returned = tuple(int(root) for root in polynomial.small_roots(X=bound, beta=float(beta)))
    if len(returned) > max_roots:
        raise SolverError("work-bound-exceeded")
    if not returned:
        raise SolverError("no-solution")
    witnesses = []
    for root in returned:
        witness = math.gcd(abs(_evaluate(coefficients, root)), modulus)
        if abs(root) >= bound or witness <= 1 or pow(witness, beta.denominator) < pow(modulus, beta.numerator):
            raise SolverError("proof-mismatch")
        witnesses.append(witness)
    roots = sorted(set(returned))
    return {
        "construction": "coppersmith-univariate",
        "proof": {"divisor_witnesses": witnesses, "roots_checked": len(returned)},
        "roots": roots,
        "verified": True,
    }


def main(arguments):
    if len(arguments) != 1:
        return _failure("invalid-arguments")
    try:
        result = _solve(_load(Path(arguments[0])))
    except SolverError as error:
        return _failure(error.code)
    except (ArithmeticError, TypeError, ValueError):
        return _failure("solver-failure")
    _emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
