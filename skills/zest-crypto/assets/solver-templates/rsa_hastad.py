#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Recover a broadcast RSA message with CRT and an exact integer root."""

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
MAX_CRT_PRODUCT_BITS = 65_536


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
    product = 1
    for modulus in moduli:
        product *= modulus
        if product.bit_length() > MAX_CRT_PRODUCT_BITS:
            raise SolverError("work-bound-exceeded")
    combined = 0
    for modulus, ciphertext in zip(moduli, ciphertexts):
        partial = product // modulus
        combined = (combined + ciphertext * partial * _inverse(partial, modulus)) % product
    message = _exact_root(combined, exponent)
    if message.bit_length() > max_root_bits:
        raise SolverError("work-bound-exceeded")
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
