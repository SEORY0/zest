# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Conservatively fingerprint local crypto challenge sources without executing them."""

import errno
import hashlib
import json
import math
import os
import shutil
import stat
import sys
from pathlib import Path

from zest_crypto_fingerprint_extract import CLUE_FAMILIES, _extract_python, _extract_text, _extract_transcript
from zest_crypto_parse import FACT_VALUE_TYPES, SCHEMA_VERSION


CAPABILITY_COMMANDS = ("python3", "sage", "z3")


class InputError(Exception):
    """A stable CLI boundary error for one input or invocation."""

    def __init__(self, path, code):
        self.path = path
        self.code = code


def _media_type(path):
    if path.suffix.lower() in (".py", ".sage"):
        return "text/x-python"
    return "text/plain"


def _locator(lines):
    unique = tuple(sorted(set(lines)))
    if len(unique) == 1:
        return "line {0}".format(unique[0])
    return "lines {0}".format(", ".join(str(line) for line in unique))


def _selected(observations, key):
    candidates = observations.get(key, ())
    if not candidates:
        return None
    first = candidates[0]
    if key == "construction.parameter_signature" and all(candidate[1] == first[1] for candidate in candidates):
        return sorted(set(value for candidate, _input_index, _lines in candidates for value in candidate)), first[1], tuple(line for _value, _input_index, lines in candidates for line in lines)
    if not all(candidate[0] == first[0] and candidate[1] == first[1] for candidate in candidates):
        return None
    return first[0], first[1], tuple(line for _value, _input_index, lines in candidates for line in lines)


def _fact(facts, key, value, status, evidence):
    item = {"id": "fact-{0:03d}".format(len(facts) + 1), "key": key, "value": value, "value_type": FACT_VALUE_TYPES[key], "status": status, "evidence": evidence}
    facts.append(item)
    return item


def _observed(facts, inputs, key, candidate):
    if candidate is None:
        return None
    value, input_index, lines = candidate
    return _fact(facts, key, value, "observed", {"input_id": inputs[input_index]["id"], "locator": _locator(lines)})


def _build_facts(inputs, observations):
    facts = []
    _observed(facts, inputs, "rsa.public_exponent", _selected(observations, "rsa.public_exponent"))
    _observed(facts, inputs, "rsa.public_exponents", _selected(observations, "rsa.public_exponents"))
    _observed(facts, inputs, "rsa.modulus", _selected(observations, "rsa.modulus"))
    moduli = _observed(facts, inputs, "rsa.moduli", _selected(observations, "rsa.moduli"))
    ciphertexts = _observed(facts, inputs, "rsa.ciphertexts", _selected(observations, "rsa.ciphertexts"))
    same_plaintext = _selected(observations, "rsa.same_plaintext")
    aligned = moduli is not None and ciphertexts is not None and same_plaintext is not None and moduli["evidence"]["input_id"] == ciphertexts["evidence"]["input_id"] == inputs[same_plaintext[1]]["id"] and len(moduli["value"]) == len(ciphertexts["value"]) and len(moduli["value"]) >= 2
    if aligned:
        _observed(facts, inputs, "rsa.same_plaintext", same_plaintext)
    scheme = _observed(facts, inputs, "signature.scheme", _selected(observations, "signature.scheme"))
    samples = _selected(observations, "signature.samples")
    if scheme is not None and samples is not None:
        values, input_index, lines = samples
        _fact(facts, "signature.sample_count", len(values), "observed", {"input_id": inputs[input_index]["id"], "locator": _locator(lines)})
        if len(values) >= 2 and len(set(sample[0] for sample in values)) < len(values):
            _fact(facts, "signature.repeated_r", True, "observed", {"input_id": inputs[input_index]["id"], "locator": _locator(lines)})
    _observed(facts, inputs, "construction.paper_ids", _selected(observations, "construction.paper_ids"))
    _observed(facts, inputs, "construction.source_anchors", _selected(observations, "construction.source_anchors"))
    clues = _observed(facts, inputs, "construction.parameter_signature", _selected(observations, "construction.parameter_signature"))
    if clues is not None:
        families = {CLUE_FAMILIES[clue] for clue in clues["value"]}
        if len(families) == 1:
            clue = clues["value"][0]
            _fact(facts, "construction.canonical_family", next(iter(families)), "inferred", {"input_id": clues["evidence"]["input_id"], "locator": clues["evidence"]["locator"], "rationale": "Exact {0} clue supports this family, but does not prove it.".format(clue)})
    if moduli is not None and len(moduli["value"]) >= 2:
        values = moduli["value"]
        if all(math.gcd(left, right) == 1 for index, left in enumerate(values) for right in values[index + 1:]):
            _fact(facts, "rsa.moduli_pairwise_coprime", True, "derived", {"source_fact_ids": [moduli["id"]], "rationale": "Pairwise gcd checks over the observed moduli were all one."})
    return facts


def _read_regular_file(raw_path, issue_path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    descriptor = None
    try:
        original = os.lstat(raw_path)
        if stat.S_ISLNK(original.st_mode):
            raise InputError(issue_path, "input-symlink")
        if not stat.S_ISREG(original.st_mode):
            raise InputError(issue_path, "input-not-file")
        if nofollow is not None:
            flags |= nofollow
        descriptor = os.open(raw_path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise InputError(issue_path, "input-not-file")
        if original.st_dev != opened.st_dev or original.st_ino != opened.st_ino:
            raise InputError(issue_path, "input-unreadable")
        handle = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = None
        with handle:
            return handle.read()
    except InputError:
        raise
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise InputError(issue_path, "input-symlink")
        raise InputError(issue_path, "input-unreadable")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _inputs(paths):
    records = []
    seen = set()
    texts = []
    for index, raw_path in enumerate(paths):
        try:
            path = Path(raw_path)
            normalized = os.path.normcase(os.path.abspath(os.path.normpath(raw_path)))
            if normalized in seen:
                raise InputError("$[{0}]".format(index + 1), "duplicate-input-path")
            content = _read_regular_file(raw_path, "$[{0}]".format(index + 1))
            text = content.decode("utf-8")
        except InputError:
            raise
        except UnicodeDecodeError:
            raise InputError("$[{0}]".format(index + 1), "input-undecodable")
        except (OSError, ValueError):
            raise InputError("$[{0}]".format(index + 1), "input-unreadable")
        seen.add(normalized)
        records.append({"id": "input-{0:03d}".format(index + 1), "path": "inputs/{0:03d}-{1}".format(index + 1, path.name), "sha256": hashlib.sha256(content).hexdigest(), "media_type": _media_type(path)})
        texts.append((path, text))
    return records, texts


def fingerprint(case_id, paths):
    """Return the versioned immutable fingerprint document for local paths."""

    inputs, texts = _inputs(paths)
    observations = {}
    for index, (path, text) in enumerate(texts):
        _extract_text(text, index, observations)
        if path.suffix.lower() in (".py", ".sage"):
            _extract_python(text, index, observations)
        else:
            _extract_transcript(text, index, observations)
    return {"schema_version": SCHEMA_VERSION, "case_id": case_id, "inputs": inputs, "facts": _build_facts(inputs, observations), "capabilities": [{"command": command, "available": shutil.which(command) is not None, "version": None} for command in CAPABILITY_COMMANDS], "constraints": {"network": "disabled"}}


def _error(error):
    return {"ok": False, "issues": [{"path": error.path, "code": error.code}]}


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) < 2 or not arguments[0]:
        print(json.dumps(_error(InputError("$", "invalid-arguments")), sort_keys=True))
        return 2
    try:
        document = fingerprint(arguments[0], arguments[1:])
    except InputError as error:
        print(json.dumps(_error(error), sort_keys=True))
        return 2
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
