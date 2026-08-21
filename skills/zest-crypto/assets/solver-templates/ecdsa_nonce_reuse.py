#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Recover a reused ECDSA nonce and verify signatures plus the public key."""

from __future__ import annotations

import json
import math
import os
import stat
import sys
from pathlib import Path


MAX_INPUT_BYTES = 1_000_000
MAX_INTEGER_BITS = 1024
MAX_JSON_DEPTH = 32
MAX_JSON_INTEGER_DIGITS = 4096
KNOWN_LARGE_PRIMES = frozenset((0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141))


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


def _integer(document, key, minimum=0):
    if type(document) is not dict:
        raise SolverError("invalid-input")
    value = document.get(key)
    if type(value) is not int or value < minimum or value.bit_length() > MAX_INTEGER_BITS:
        raise SolverError("invalid-input")
    return value


def _is_prime_64(value):
    if value < 2:
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


def _require_prime(value, code):
    if value in KNOWN_LARGE_PRIMES:
        return
    if value.bit_length() > 64:
        raise SolverError("unsupported-domain")
    if not _is_prime_64(value):
        raise SolverError(code)


def _extended_gcd(left, right):
    old_r, r = left, right
    old_s, s = 1, 0
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_r, old_s


def _inverse(value, modulus, code):
    divisor, coefficient = _extended_gcd(value % modulus, modulus)
    if divisor != 1:
        raise SolverError(code)
    inverse = coefficient % modulus
    if (value * inverse) % modulus != 1:
        raise SolverError("proof-mismatch")
    return inverse


def _on_curve(point, curve):
    x, y = point
    p, a, b = curve
    return 0 <= x < p and 0 <= y < p and (y * y - x * x * x - a * x - b) % p == 0


def _point_add(left, right, curve):
    if left is None:
        return right
    if right is None:
        return left
    p, a, _b = curve
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + a) * _inverse(2 * y1, p, "invalid-curve") % p
    elif x1 != x2:
        slope = (y2 - y1) * _inverse(x2 - x1, p, "invalid-curve") % p
    else:
        raise SolverError("invalid-curve")
    x3 = (slope * slope - x1 - x2) % p
    result = (x3, (slope * (x1 - x3) - y1) % p)
    if not _on_curve(result, curve):
        raise SolverError("invalid-curve")
    return result


def _scalar_multiply(scalar, point, curve):
    result = None
    addend = point
    remaining = scalar
    while remaining:
        if remaining & 1:
            result = _point_add(result, addend, curve)
        addend = _point_add(addend, addend, curve)
        remaining >>= 1
    return result


def _parse_signature(raw, order):
    r = _integer(raw, "r", 1)
    s = _integer(raw, "s", 1)
    z = _integer(raw, "z", 0)
    if r >= order or s >= order:
        raise SolverError("invalid-input")
    return r, s, z % order


def _solve(document):
    curve_document = document.get("curve")
    p = _integer(curve_document, "p", 5)
    curve = (p, _integer(curve_document, "a") % p, _integer(curve_document, "b") % p)
    generator = (_integer(curve_document, "gx"), _integer(curve_document, "gy"))
    order = _integer(document, "order", 3)
    _require_prime(p, "invalid-field")
    _require_prime(order, "invalid-order")
    if (4 * pow(curve[1], 3, p) + 27 * pow(curve[2], 2, p)) % p == 0:
        raise SolverError("invalid-curve")
    public_document = document.get("public_key")
    public_key = (_integer(public_document, "x"), _integer(public_document, "y"))
    raw_signatures = document.get("signatures")
    if type(raw_signatures) is not list or len(raw_signatures) != 2:
        raise SolverError("invalid-input")
    signatures = tuple(_parse_signature(raw, order) for raw in raw_signatures)
    if generator is None or public_key is None or not _on_curve(generator, curve) or not _on_curve(public_key, curve):
        raise SolverError("invalid-curve")
    if _scalar_multiply(order, generator, curve) is not None:
        raise SolverError("invalid-curve")
    first, second = signatures
    if first[0] != second[0]:
        raise SolverError("repeated-r-required")
    nonce = (first[2] - second[2]) * _inverse(first[1] - second[1], order, "non-invertible-signature") % order
    private_scalar = (first[1] * nonce - first[2]) * _inverse(first[0], order, "non-invertible-signature") % order
    nonce_point = _scalar_multiply(nonce, generator, curve)
    signatures_verified = 0
    for r, s, z in signatures:
        equation = (s * nonce - z - r * private_scalar) % order == 0
        inverse_s = _inverse(s, order, "non-invertible-signature")
        verifier_point = _point_add(
            _scalar_multiply((z * inverse_s) % order, generator, curve),
            _scalar_multiply((r * inverse_s) % order, public_key, curve),
            curve,
        )
        if equation and verifier_point is not None and verifier_point[0] % order == r:
            signatures_verified += 1
    public_key_matches = _scalar_multiply(private_scalar, generator, curve) == public_key
    nonce_matches = nonce_point is not None and nonce_point[0] % order == first[0]
    if signatures_verified != 2 or not public_key_matches or not nonce_matches:
        raise SolverError("proof-mismatch")
    return {
        "construction": "ecdsa-reused-nonce",
        "k": nonce,
        "private_scalar": private_scalar,
        "proof": {"public_key_matches": True, "signatures_verified": signatures_verified},
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
