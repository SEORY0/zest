#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Recover a reused ECDSA nonce on proven small or audited secp256k1/P-256 domains."""

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
# Canonical (p, a, b, gx, gy, order) tuples; other large domains are unsupported.
KNOWN_STANDARD_DOMAINS = frozenset(((0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0, 7, 55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141), (115792089210356248762697446949407573530086143415290314195533631308867097853951, 115792089210356248762697446949407573530086143415290314195533631308867097853948, 41058363725152142129326129780047268409114441015993725554835256314039467401291, 48439561293906451759052585252797914202762949526041747995844080717082404635286, 36134250956749795798585127919587881956611106672985015071877198253568414405109, 115792089210356248762697446949407573529996955224135760342422259061068512044369)))
NONCE_RELATIONS = ((1, "same"), (-1, "opposite"))


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


def _require_prime_64(value, code):
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


def _candidate_proof(signatures, nonce, second_nonce_sign, private_scalar, generator, public_key, curve, order):
    if not 0 < nonce < order or not 0 < private_scalar < order:
        return None
    if _scalar_multiply(private_scalar, generator, curve) != public_key:
        return None
    nonce_signs = (1, second_nonce_sign)
    nonce_points = []
    for (r, s, z), nonce_sign in zip(signatures, nonce_signs):
        signature_nonce = nonce * nonce_sign % order
        nonce_point = _scalar_multiply(signature_nonce, generator, curve)
        if nonce_point is None or nonce_point[0] % order != r:
            return None
        inverse_s = _inverse(s, order, "non-invertible-signature")
        verifier_point = _point_add(
            _scalar_multiply((z * inverse_s) % order, generator, curve),
            _scalar_multiply((r * inverse_s) % order, public_key, curve),
            curve,
        )
        private_equation = (s * signature_nonce - z - r * private_scalar) % order == 0
        if not private_equation or verifier_point != nonce_point:
            return None
        nonce_points.append(nonce_point)
    p = curve[0]
    expected_second_point = nonce_points[0] if second_nonce_sign == 1 else (nonce_points[0][0], -nonce_points[0][1] % p)
    if nonce_points[1] != expected_second_point:
        return None
    return {
        "nonce_points_verified": len(nonce_points),
        "nonce_relation_matches": True,
        "nonce_signs": nonce_signs,
        "public_key_matches": True,
        "signatures_verified": len(signatures),
    }


def _solve(document):
    curve_document = document.get("curve")
    p = _integer(curve_document, "p", 5)
    curve = (p, _integer(curve_document, "a") % p, _integer(curve_document, "b") % p)
    generator = (_integer(curve_document, "gx"), _integer(curve_document, "gy"))
    order = _integer(document, "order", 3)
    if p.bit_length() > 64 or order.bit_length() > 64:
        if (*curve, *generator, order) not in KNOWN_STANDARD_DOMAINS:
            raise SolverError("unsupported-domain")
    else:
        _require_prime_64(p, "invalid-field")
        _require_prime_64(order, "invalid-order")
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
    if first == second:
        raise SolverError("ambiguous-nonce-relation")
    inverse_r = _inverse(first[0], order, "non-invertible-signature")
    candidates = []
    for second_nonce_sign, nonce_relation in NONCE_RELATIONS:
        denominator = (first[1] - second_nonce_sign * second[1]) % order
        if math.gcd(denominator, order) != 1:
            continue
        nonce = (first[2] - second[2]) * _inverse(denominator, order, "non-invertible-signature") % order
        private_scalar = (first[1] * nonce - first[2]) * inverse_r % order
        proof = _candidate_proof(
            signatures, nonce, second_nonce_sign, private_scalar,
            generator, public_key, curve, order,
        )
        if proof is not None:
            candidates.append((nonce, private_scalar, nonce_relation, proof))
    if len(candidates) > 1:
        raise SolverError("ambiguous-nonce-relation")
    if not candidates:
        raise SolverError("proof-mismatch")
    nonce, private_scalar, nonce_relation, proof = candidates[0]
    return {
        "construction": "ecdsa-reused-nonce",
        "k": nonce,
        "nonce_relation": nonce_relation,
        "private_scalar": private_scalar,
        "proof": proof,
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
