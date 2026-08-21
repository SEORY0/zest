#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Recover a Wiener-vulnerable RSA key and prove factorization and round trip."""

from __future__ import annotations

import json
import math
import os
import stat
import sys
from pathlib import Path


MAX_INPUT_BYTES = 1_000_000
MAX_INTEGER_BITS = 16_384
MAX_JSON_DEPTH = 32
MAX_JSON_INTEGER_DIGITS = 4096
PRIME_PROOF_BITS = 64


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


def _integer(document, key, minimum):
    value = document.get(key)
    if type(value) is not int or value < minimum or value.bit_length() > MAX_INTEGER_BITS:
        raise SolverError("invalid-input")
    return value


def _is_prime(value):
    if value < 2 or value.bit_length() > PRIME_PROOF_BITS:
        return False
    for divisor in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value % divisor == 0:
            return value == divisor
    odd_part = value - 1
    twos = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        twos += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        reduced_base = base % value
        if reduced_base == 0:
            continue
        witness = pow(reduced_base, odd_part, value)
        if witness in (1, value - 1):
            continue
        for _round in range(twos - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


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
        if p > 1 and q > 1 and p * q == n:
            if p == q or not _is_prime(p) or not _is_prime(q):
                raise SolverError("invalid-factorization")
            if (e * d) % ((p - 1) * (q - 1)) == 1:
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
