#!/usr/bin/env sage
"""Run a bounded monic univariate Coppersmith instance and verify every root."""

import json
import math
import sys
from pathlib import Path

MAX_INPUT_BYTES = 1_000_000
MAX_INTEGER_BITS = 16_384
MAX_DEGREE = 16


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
        with path.open("r", encoding="utf-8") as handle:
            document = json.load(handle, parse_constant=_reject_constant)
    except (OSError, UnicodeError):
        raise SolverError("input-unreadable")
    except (json.JSONDecodeError, RecursionError):
        raise SolverError("invalid-json")
    if type(document) is not dict:
        raise SolverError("invalid-input")
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
    beta = document.get("beta")
    coefficients = document.get("coefficients")
    if type(beta) not in (int, float) or type(beta) is bool or not math.isfinite(beta) or beta <= 0 or beta > 1:
        raise SolverError("invalid-beta")
    if bound >= modulus or bound.bit_length() > MAX_INTEGER_BITS or max_roots > 1024:
        raise SolverError("invalid-bound")
    if type(coefficients) is not list or len(coefficients) < 2 or len(coefficients) > MAX_DEGREE + 1:
        raise SolverError("invalid-input")
    if any(type(value) is not int or value.bit_length() > MAX_INTEGER_BITS for value in coefficients):
        raise SolverError("invalid-input")
    if coefficients[-1] % modulus != 1:
        raise SolverError("polynomial-not-monic")
    return modulus, tuple(coefficients), bound, float(beta), max_roots


def _evaluate(coefficients, value, modulus):
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * value + coefficient) % modulus
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
    returned = tuple(int(root) for root in polynomial.small_roots(X=bound, beta=beta))
    if len(returned) > max_roots:
        raise SolverError("work-bound-exceeded")
    if not returned:
        raise SolverError("no-solution")
    if any(abs(root) >= bound or _evaluate(coefficients, root, modulus) != 0 for root in returned):
        raise SolverError("proof-mismatch")
    roots = sorted(set(returned))
    return {
        "construction": "coppersmith-univariate",
        "proof": {"roots_checked": len(returned)},
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
