#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Recover a broadcast RSA message with CRT and an exact integer root."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path


MAX_INPUT_BYTES = 1_000_000
MAX_INTEGER_BITS = 16_384


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


def _integer(value, minimum, maximum_bits=MAX_INTEGER_BITS):
    if type(value) is not int or value < minimum or value.bit_length() > maximum_bits:
        raise SolverError("invalid-input")
    return value


def _integer_list(document, key, minimum):
    values = document.get(key)
    if type(values) is not list or not values or len(values) > 64:
        raise SolverError("invalid-input")
    return tuple(_integer(value, minimum) for value in values)


def _extended_gcd(left, right):
    old_r, r = left, right
    old_s, s = 1, 0
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_r, old_s


def _inverse(value, modulus):
    divisor, coefficient = _extended_gcd(value, modulus)
    if divisor != 1:
        raise SolverError("moduli-not-coprime")
    inverse = coefficient % modulus
    if (value * inverse) % modulus != 1:
        raise SolverError("proof-mismatch")
    return inverse


def _exact_root(value, exponent):
    if value == 0:
        return 0
    low = 0
    high = 1 << ((value.bit_length() + exponent - 1) // exponent + 1)
    while low + 1 < high:
        middle = (low + high) // 2
        if pow(middle, exponent) <= value:
            low = middle
        else:
            high = middle
    if pow(low, exponent) != value:
        raise SolverError("inexact-root")
    return low


def _solve(document):
    exponent = _integer(document.get("exponent"), 2, 8)
    max_root_bits = _integer(document.get("max_root_bits"), 1, 16)
    moduli = _integer_list(document, "moduli", 3)
    ciphertexts = _integer_list(document, "ciphertexts", 0)
    if max_root_bits > 4096 or len(moduli) != len(ciphertexts) or len(moduli) < exponent:
        raise SolverError("invalid-input")
    for index, modulus in enumerate(moduli):
        if ciphertexts[index] >= modulus:
            raise SolverError("invalid-input")
        for other in moduli[index + 1 :]:
            if math.gcd(modulus, other) != 1:
                raise SolverError("moduli-not-coprime")
    product = math.prod(moduli)
    if product.bit_length() > max_root_bits * exponent:
        raise SolverError("work-bound-exceeded")
    combined = 0
    for modulus, ciphertext in zip(moduli, ciphertexts):
        partial = product // modulus
        combined = (combined + ciphertext * partial * _inverse(partial, modulus)) % product
    message = _exact_root(combined, exponent)
    recomputed = [pow(message, exponent, modulus) for modulus in moduli]
    if recomputed != list(ciphertexts):
        raise SolverError("proof-mismatch")
    return {
        "construction": "rsa-hastad-broadcast",
        "message": message,
        "proof": {"combined_power": combined, "recomputed": recomputed},
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
