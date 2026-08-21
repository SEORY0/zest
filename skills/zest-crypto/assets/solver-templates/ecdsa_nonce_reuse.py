#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Recover a reused ECDSA nonce on proven small or audited secp256k1/P-256 domains."""

import json
import math
import os
import stat
import sys


MAX_INPUT_BYTES = 1_000_000
MAX_INTEGER_BITS = 1024
MAX_JSON_DEPTH = 32
MAX_JSON_INTEGER_DIGITS = 4096
# Canonical (p, a, b, gx, gy, order) tuples; other large domains are unsupported.
KNOWN_STANDARD_DOMAINS = frozenset((
    # NIST P-256
    (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff, 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc, 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b, 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
    # secp256k1
    (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, 0, 7, 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141)))


class SolverError(Exception):
    pass


def _emit(document, exit_code=0):
    sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    return exit_code


def _failure(code):
    return _emit({"error": {"code": code}, "verified": False}, 2)


def _parse_json_integer(token):
    if len(token.lstrip("-")) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError
    return int(token)


def _parse_json_float(token):
    if len(token) > 128:
        raise ValueError
    value = float(token)
    if not math.isfinite(value):
        raise ValueError
    return value


def _unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError
    return result


def _check_depth(document):
    pending = [(document, 1)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise SolverError("invalid-json")
        if type(value) not in (dict, list):
            continue
        children = value.values() if type(value) is dict else value
        pending.extend((item, depth + 1) for item in children)


def _open_regular(path, flags):
    extra_flags = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags | extra_flags)


def _read_regular(path):
    try:
        with open(path, "rb", opener=_open_regular) as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise SolverError("input-unreadable")
            content = handle.read(MAX_INPUT_BYTES + 1)
    except (OSError, MemoryError):
        raise SolverError("input-unreadable")
    if len(content) > MAX_INPUT_BYTES:
        raise SolverError("input-too-large")
    try:
        return content.decode("utf-8")
    except (UnicodeError, MemoryError):
        raise SolverError("input-unreadable")


def _load(path):
    try:
        document = json.loads(_read_regular(path), object_pairs_hook=_unique_object,
                              parse_constant=_parse_json_float, parse_float=_parse_json_float,
                              parse_int=_parse_json_integer)
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
    for divisor in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value % divisor == 0:
            return value == divisor
    odd_part = value - 1
    twos = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        twos += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        witness = pow(base, odd_part, value)
        if witness in (0, 1, value - 1):
            continue
        for _round in range(twos - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def _inverse(value, modulus, code):
    try:
        inverse = pow(value, -1, modulus)
    except ValueError:
        raise SolverError(code)
    if (value * inverse) % modulus != 1:
        raise SolverError("proof-mismatch")
    return inverse


def _on_curve(point, curve):
    (x, y), (p, a, b) = point, curve
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
    else:
        slope = (y2 - y1) * _inverse(x2 - x1, p, "invalid-curve") % p
    x3 = (slope * slope - x1 - x2) % p
    result = (x3, (slope * (x1 - x3) - y1) % p)
    if not _on_curve(result, curve):
        raise SolverError("invalid-curve")
    return result


def _scalar_multiply(scalar, point, curve):
    result = None
    addend = point
    remaining_scalar = scalar
    while remaining_scalar:
        if remaining_scalar & 1:
            result = _point_add(result, addend, curve)
        addend = _point_add(addend, addend, curve)
        remaining_scalar >>= 1
    return result


def _parse_signature(raw, order):
    r = _integer(raw, "r", 1)
    s = _integer(raw, "s", 1)
    if r >= order or s >= order:
        raise SolverError("invalid-input")
    return r, s, _integer(raw, "z", 0) % order


def _candidate_proof(signatures, nonce, second_nonce_sign, private_scalar, generator, public_key, curve, order):
    if not (0 < nonce < order and 0 < private_scalar < order):
        return None
    if _scalar_multiply(private_scalar, generator, curve) != public_key:
        return None
    nonce_signs = (1, second_nonce_sign)
    nonce_points = []
    for (r, s, z), nonce_sign in zip(signatures, nonce_signs):
        signature_nonce = nonce * nonce_sign % order
        nonce_point = _scalar_multiply(signature_nonce, generator, curve)
        inverse_s = _inverse(s, order, "non-invertible-signature")
        generator_scalar = z * inverse_s % order
        public_scalar = r * inverse_s % order
        generator_contribution = _scalar_multiply(generator_scalar, generator, curve)
        public_contribution = _scalar_multiply(public_scalar, public_key, curve)
        verifier_point = _point_add(generator_contribution, public_contribution, curve)
        if (nonce_point is None or nonce_point[0] % order != r
                or (s * signature_nonce - z - r * private_scalar) % order != 0
                or verifier_point != nonce_point):
            return None
        nonce_points.append(nonce_point)
    expected_second_point = (nonce_points[0] if second_nonce_sign == 1
                             else (nonce_points[0][0], -nonce_points[0][1] % curve[0]))
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
    raw_a = _integer(curve_document, "a")
    raw_b = _integer(curve_document, "b")
    curve = (p, raw_a % p, raw_b % p)
    generator = (_integer(curve_document, "gx"), _integer(curve_document, "gy"))
    order = _integer(document, "order", 3)
    if p.bit_length() > 64 or order.bit_length() > 64:
        if (p, raw_a, raw_b, *generator, order) not in KNOWN_STANDARD_DOMAINS:
            raise SolverError("unsupported-domain")
    else:
        for value, code in ((p, "invalid-field"), (order, "invalid-order")):
            if not _is_prime_64(value):
                raise SolverError(code)
    if (4 * pow(curve[1], 3, p) + 27 * pow(curve[2], 2, p)) % p == 0:
        raise SolverError("invalid-curve")
    public_key = (_integer(document.get("public_key"), "x"), _integer(document.get("public_key"), "y"))
    raw_signatures = document.get("signatures")
    if type(raw_signatures) is not list or len(raw_signatures) != 2:
        raise SolverError("invalid-input")
    signatures = tuple(_parse_signature(raw, order) for raw in raw_signatures)
    if not _on_curve(generator, curve) or not _on_curve(public_key, curve):
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
    for second_nonce_sign, nonce_relation in ((1, "same"), (-1, "opposite")):
        denominator = (first[1] - second_nonce_sign * second[1]) % order
        if math.gcd(denominator, order) != 1:
            continue
        nonce = (first[2] - second[2]) * _inverse(denominator, order, "non-invertible-signature") % order
        private_scalar = (first[1] * nonce - first[2]) * inverse_r % order
        proof = _candidate_proof(signatures, nonce, second_nonce_sign, private_scalar,
                                 generator, public_key, curve, order)
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
        return _emit(_solve(_load(arguments[0])))
    except SolverError as error:
        return _failure(str(error))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
