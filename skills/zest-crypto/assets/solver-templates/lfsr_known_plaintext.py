#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Recover a bounded Galois LFSR from known plaintext and prove a file digest."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


MAX_HEX_FILE_BYTES = 2_000_000
LOWER_HEX = frozenset("0123456789abcdef")


class SolverError(Exception):
    def __init__(self, code):
        self.code = code


def _emit(document):
    sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")


def _failure(code):
    _emit({"error": {"code": code}, "verified": False})
    return 2


def _read_hex(path):
    try:
        if path.stat().st_size > MAX_HEX_FILE_BYTES:
            raise SolverError("input-too-large")
        encoded = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise SolverError("input-unreadable")
    if not encoded or len(encoded) % 2 or any(character not in LOWER_HEX for character in encoded):
        raise SolverError("invalid-hex")
    try:
        return bytes.fromhex(encoded)
    except ValueError:
        raise SolverError("invalid-hex")


def _parse_small_integer(raw, minimum, maximum):
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 10:
        raise SolverError("invalid-arguments")
    value = int(raw)
    if value < minimum or value > maximum:
        raise SolverError("invalid-arguments")
    return value


def _step(state, tap_mask, width):
    output = state & 1
    next_state = state >> 1
    if output:
        next_state ^= tap_mask
    return output, next_state & ((1 << width) - 1)


def _keystream(initial_state, tap_mask, width, byte_count):
    state = initial_state
    stream = bytearray()
    for _byte_index in range(byte_count):
        value = 0
        for bit_index in range(8):
            output, state = _step(state, tap_mask, width)
            value |= output << bit_index
        stream.append(value)
    return bytes(stream)


def _recover(observed, width, max_candidates):
    mask = (1 << width) - 1
    candidate_count = mask * mask
    if candidate_count > max_candidates:
        raise SolverError("work-bound-exceeded")
    matches = []
    for initial_state in range(1, mask + 1):
        for tap_mask in range(1, mask + 1):
            if _keystream(initial_state, tap_mask, width, len(observed)) == observed:
                matches.append((initial_state, tap_mask))
                if len(matches) > 1:
                    raise SolverError("ambiguous-solution")
    if not matches:
        raise SolverError("no-solution")
    return matches[0]


def _solve(ciphertext, known_plaintext, expected_digest, width, max_candidates):
    if len(ciphertext) > 1_000_000 or len(known_plaintext) > len(ciphertext):
        raise SolverError("invalid-input")
    if len(known_plaintext) * 8 < width * 4:
        raise SolverError("insufficient-known-plaintext")
    if len(expected_digest) != 64 or any(character not in LOWER_HEX for character in expected_digest):
        raise SolverError("invalid-arguments")
    observed = bytes(left ^ right for left, right in zip(ciphertext, known_plaintext))
    initial_state, tap_mask = _recover(observed, width, max_candidates)
    stream = _keystream(initial_state, tap_mask, width, len(ciphertext))
    plaintext = bytes(left ^ right for left, right in zip(ciphertext, stream))
    known_prefix_replayed = plaintext[: len(known_plaintext)] == known_plaintext
    ciphertext_replayed = bytes(left ^ right for left, right in zip(plaintext, stream)) == ciphertext
    digest = hashlib.sha256(plaintext).hexdigest()
    if not known_prefix_replayed or not ciphertext_replayed or digest != expected_digest:
        raise SolverError("proof-mismatch")
    return {
        "construction": "galois-lfsr-known-plaintext",
        "initial_state": initial_state,
        "plaintext_hex": plaintext.hex(),
        "plaintext_sha256": digest,
        "proof": {"ciphertext_replayed": True, "known_prefix_replayed": True},
        "tap_mask": tap_mask,
        "verified": True,
        "width": width,
    }


def main(arguments):
    if len(arguments) != 5:
        return _failure("invalid-arguments")
    try:
        ciphertext = _read_hex(Path(arguments[0]))
        known_plaintext = _read_hex(Path(arguments[1]))
        width = _parse_small_integer(arguments[3], 2, 12)
        max_candidates = _parse_small_integer(arguments[4], 1, 2_000_000)
        result = _solve(ciphertext, known_plaintext, arguments[2], width, max_candidates)
    except SolverError as error:
        return _failure(error.code)
    _emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
