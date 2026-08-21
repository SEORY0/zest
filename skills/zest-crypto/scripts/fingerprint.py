# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Conservatively fingerprint local crypto challenge sources without executing them."""

import ast
import hashlib
import json
import math
import re
import shutil
import sys
from pathlib import Path

from zest_crypto_parse import FACT_VALUE_TYPES


CAPABILITY_COMMANDS = ("python3", "sage", "z3")
DOI_URL = re.compile(r"https://(?:dx\.)?doi\.org/(10\.\d{4,9}/[-._;()/:A-Za-z0-9]+)", re.IGNORECASE)
EPRINT_URL = re.compile(r"https://eprint\.iacr\.org/(\d{4}/\d+)", re.IGNORECASE)
HEX_INTEGER = re.compile(r"^\s*(n|modulus|e|public_exponent|c|ciphertext)\s*=\s*(0x[0-9a-fA-F]+)\s*$", re.MULTILINE)
CLUE_TOKEN = re.compile(r"(?<![A-Za-z0-9_])(small_roots|LLL|EllipticCurve|MT19937|LFSR|Goldwasser|FROST|UOV|CSIDH|repeated-round|slide)(?![A-Za-z0-9_])")
CLUE_FAMILIES = {
    "small_roots": "lattice.coppersmith.univariate-small-root",
    "LLL": "lattice.lll",
    "EllipticCurve": "ecc.elliptic-curve",
    "MT19937": "prng.mt19937",
    "LFSR": "stream.lfsr",
    "Goldwasser": "oracle.goldwasser-micali.replication",
    "FROST": "paper.frost.threshold-signature",
    "UOV": "paper.uov.wrapper-structure",
    "CSIDH": "paper.csidh.auxiliary-point-leak",
    "repeated-round": "symmetric.slide.periodic-round",
    "slide": "symmetric.slide.periodic-round",
}


class InputError(Exception):
    """A stable CLI boundary error for one input or invocation."""

    def __init__(self, path, code):
        self.path = path
        self.code = code


def _media_type(path):
    if path.suffix.lower() in (".py", ".sage"):
        return "text/x-python"
    return "text/plain"


def _line(text, offset):
    return text.count("\n", 0, offset) + 1


def _add(observations, key, value, input_index, line):
    observations.setdefault(key, []).append((value, input_index, line))


def _literal(node):
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def _targets(node):
    if isinstance(node, ast.Assign):
        return node.targets, node.value
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return (node.target,), node.value
    return (), None


def _names(targets):
    return tuple(target.id for target in targets if isinstance(target, ast.Name))


def _integer_list(value):
    if not isinstance(value, (list, tuple)):
        return None
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in value):
        return None
    return list(value)


def _string_list(value):
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) and item for item in value):
        return None
    return list(value)


def _signature_samples(value):
    if not isinstance(value, (list, tuple)) or not value:
        return None
    samples = []
    for sample in value:
        if not isinstance(sample, (list, tuple)) or len(sample) < 2:
            return None
        if not all(isinstance(item, int) and not isinstance(item, bool) for item in sample):
            return None
        samples.append(tuple(sample))
    return samples


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _extract_python(text, input_index, observations):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return
    call_names = tuple(name for name in (_call_name(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)) if name is not None)
    _extract_clues("\n".join(call_names), input_index, text, observations)
    for node in ast.walk(tree):
        targets, value_node = _targets(node)
        if value_node is None:
            continue
        value = _literal(value_node)
        if value is None:
            continue
        for name in _names(targets):
            lowered = name.lower()
            if isinstance(value, bool) and lowered == "same_plaintext":
                _add(observations, "rsa.same_plaintext", value, input_index, node.lineno)
            elif isinstance(value, int) and not isinstance(value, bool):
                if lowered in ("e", "public_exponent"):
                    _add(observations, "rsa.public_exponent", value, input_index, node.lineno)
                elif lowered in ("n", "modulus"):
                    _add(observations, "rsa.modulus", value, input_index, node.lineno)
            elif isinstance(value, str) and lowered in ("scheme", "signature_scheme") and value.lower() == "ecdsa":
                _add(observations, "signature.scheme", "ecdsa", input_index, node.lineno)
            values = _integer_list(value)
            if values is not None:
                if lowered in ("moduli", "ns"):
                    _add(observations, "rsa.moduli", values, input_index, node.lineno)
                elif lowered in ("ciphertexts", "cts"):
                    _add(observations, "rsa.ciphertexts", values, input_index, node.lineno)
            strings = _string_list(value)
            if strings is not None and lowered == "source_anchors":
                _add(observations, "construction.source_anchors", strings, input_index, node.lineno)
            samples = _signature_samples(value)
            if samples is not None and lowered in ("signatures", "sigs"):
                _add(observations, "signature.samples", samples, input_index, node.lineno)


def _extract_transcript(text, input_index, observations):
    for match in HEX_INTEGER.finditer(text):
        label = match.group(1)
        value = int(match.group(2), 16)
        line = _line(text, match.start())
        if label in ("n", "modulus"):
            _add(observations, "rsa.modulus", value, input_index, line)
        elif label in ("e", "public_exponent"):
            _add(observations, "rsa.public_exponent", value, input_index, line)
        else:
            _add(observations, "rsa.ciphertexts", [value], input_index, line)


def _extract_clues(text, input_index, source_text, observations):
    clues = sorted(set(match.group(1) for match in CLUE_TOKEN.finditer(text)))
    if clues:
        first = min((_line(source_text, source_text.find(clue)) for clue in clues))
        _add(observations, "construction.parameter_signature", clues, input_index, first)


def _extract_text(text, input_index, observations):
    paper_ids = sorted(set("doi:{0}".format(match.group(1)) for match in DOI_URL.finditer(text)).union("eprint:{0}".format(match.group(1)) for match in EPRINT_URL.finditer(text)))
    if paper_ids:
        first_match = DOI_URL.search(text) or EPRINT_URL.search(text)
        _add(observations, "construction.paper_ids", paper_ids, input_index, _line(text, first_match.start()))
    _extract_clues(text, input_index, text, observations)


def _selected(observations, key):
    candidates = observations.get(key, ())
    if not candidates:
        return None
    first = candidates[0]
    if all(candidate[0] == first[0] for candidate in candidates):
        return first
    return None


def _fact(facts, key, value, status, evidence):
    item = {"id": "fact-{0:03d}".format(len(facts) + 1), "key": key, "value": value, "value_type": FACT_VALUE_TYPES[key], "status": status, "evidence": evidence}
    facts.append(item)
    return item


def _observed(facts, inputs, key, candidate):
    if candidate is None:
        return None
    value, input_index, line = candidate
    return _fact(facts, key, value, "observed", {"input_id": inputs[input_index]["id"], "locator": "line {0}".format(line)})


def _build_facts(inputs, observations):
    facts = []
    exponent = _observed(facts, inputs, "rsa.public_exponent", _selected(observations, "rsa.public_exponent"))
    del exponent
    modulus = _observed(facts, inputs, "rsa.modulus", _selected(observations, "rsa.modulus"))
    del modulus
    moduli = _observed(facts, inputs, "rsa.moduli", _selected(observations, "rsa.moduli"))
    ciphertexts = _observed(facts, inputs, "rsa.ciphertexts", _selected(observations, "rsa.ciphertexts"))
    same_plaintext = _selected(observations, "rsa.same_plaintext")
    if same_plaintext is not None:
        value = same_plaintext[0]
        aligned = moduli is not None and ciphertexts is not None and len(moduli["value"]) == len(ciphertexts["value"]) and len(moduli["value"]) >= 2
        if value is False or aligned:
            _observed(facts, inputs, "rsa.same_plaintext", same_plaintext)
    scheme = _observed(facts, inputs, "signature.scheme", _selected(observations, "signature.scheme"))
    samples = _selected(observations, "signature.samples")
    if scheme is not None and samples is not None:
        values, input_index, line = samples
        _fact(facts, "signature.sample_count", len(values), "observed", {"input_id": inputs[input_index]["id"], "locator": "line {0}".format(line)})
        if len(values) >= 2 and len(set(sample[0] for sample in values)) < len(values):
            _fact(facts, "signature.repeated_r", True, "observed", {"input_id": inputs[input_index]["id"], "locator": "line {0}".format(line)})
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


def _inputs(paths):
    records = []
    seen = set()
    texts = []
    for index, raw_path in enumerate(paths):
        try:
            path = Path(raw_path)
            if path.is_symlink():
                raise InputError("$[{0}]".format(index + 1), "input-symlink")
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                raise InputError("$[{0}]".format(index + 1), "input-not-file")
            normalized = str(resolved)
            if normalized in seen:
                raise InputError("$[{0}]".format(index + 1), "duplicate-input-path")
            seen.add(normalized)
            content = resolved.read_bytes()
            text = content.decode("utf-8")
        except InputError:
            raise
        except UnicodeDecodeError:
            raise InputError("$[{0}]".format(index + 1), "input-undecodable")
        except (OSError, ValueError):
            raise InputError("$[{0}]".format(index + 1), "input-unreadable")
        records.append({"id": "input-{0:03d}".format(index + 1), "path": "inputs/{0:03d}-{1}".format(index + 1, resolved.name), "sha256": hashlib.sha256(content).hexdigest(), "media_type": _media_type(resolved)})
        texts.append((resolved, text))
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
    return {"schema_version": 1, "case_id": case_id, "inputs": inputs, "facts": _build_facts(inputs, observations), "capabilities": [{"command": command, "available": shutil.which(command) is not None, "version": None} for command in CAPABILITY_COMMANDS], "constraints": {"network": "disabled"}}


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
