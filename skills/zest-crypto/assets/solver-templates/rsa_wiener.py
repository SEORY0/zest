#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Recover a Wiener-vulnerable RSA key and prove factorization and round trip."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path


MAX_INPUT_BYTES = 1_000_000
MAX_INTEGER_BITS = 16_384


class SolverError(Exception):
    """A stable expected failure at the untrusted CLI boundary."""

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


def _integer(document, key, minimum):
    value = document.get(key)
    if type(value) is not int or value < minimum or value.bit_length() > MAX_INTEGER_BITS:
        raise SolverError("invalid-input")
    return value


def _recover(n, e, limit):
    numerator, denominator = e, n
    previous_numerator, current_numerator = 0, 1
    previous_denominator, current_denominator = 1, 0
    checked = 0
    while denominator and checked < limit:
        quotient, remainder = divmod(numerator, denominator)
        numerator, denominator = denominator, remainder
        next_numerator = quotient * current_numerator + previous_numerator
        next_denominator = quotient * current_denominator + previous_denominator
        previous_numerator, current_numerator = current_numerator, next_numerator
        previous_denominator, current_denominator = current_denominator, next_denominator
        k, d = current_numerator, current_denominator
        checked += 1
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        factor_sum = n - phi + 1
        discriminant = factor_sum * factor_sum - 4 * n
        if discriminant < 0:
            continue
        root = math.isqrt(discriminant)
        if root * root != discriminant or (factor_sum + root) % 2:
            continue
        p = (factor_sum + root) // 2
        q = (factor_sum - root) // 2
        if p > 1 and q > 1 and p * q == n and (e * d) % ((p - 1) * (q - 1)) == 1:
            return d, tuple(sorted((p, q)))
    raise SolverError("no-solution")


def _solve(document):
    n = _integer(document, "n", 3)
    e = _integer(document, "e", 2)
    ciphertext = _integer(document, "ciphertext", 0)
    limit = _integer(document, "max_convergents", 1)
    if ciphertext >= n or e >= n or limit > 4096:
        raise SolverError("invalid-input")
    d, factors = _recover(n, e, limit)
    message = pow(ciphertext, d, n)
    reencrypted = pow(message, e, n)
    if reencrypted != ciphertext:
        raise SolverError("proof-mismatch")
    return {
        "construction": "rsa-wiener",
        "d": d,
        "factors": list(factors),
        "message": message,
        "proof": {"ciphertext": ciphertext, "reencrypted": reencrypted},
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
