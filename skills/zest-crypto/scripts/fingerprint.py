# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Conservatively fingerprint local crypto challenge sources without executing them."""

import ast
import errno
import hashlib
import json
import math
import os
import re
import shutil
import stat
import sys
import unicodedata
from pathlib import Path

from zest_crypto_parse import FACT_VALUE_TYPES


CAPABILITY_COMMANDS = ("python3", "sage", "z3")
DOI_URL = re.compile(r"https://(?:dx\.)?doi\.org/", re.IGNORECASE)
DOI_IDENTIFIER = re.compile(r"10\.\d{4,9}/[-._()/:A-Za-z0-9]+", re.IGNORECASE)
EPRINT_URL = re.compile(r"https://eprint\.iacr\.org/(\d{4}/\d+)(?:\.pdf)?", re.IGNORECASE)
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
ANCHOR_ASCII = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-/")
URL_OPENERS = frozenset(("\"", "'", "<", "(", "[", "{"))
URL_CLOSERS = frozenset(("\"", "'", "<", ">", ")", "]", "}"))
DOI_TOKEN_STOPPERS = frozenset(("\"", "'", "<", ">", "[", "]", "{", "}"))


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


def _locator(lines):
    unique = tuple(sorted(set(lines)))
    if len(unique) == 1:
        return "line {0}".format(unique[0])
    return "lines {0}".format(", ".join(str(line) for line in unique))


def _add(observations, key, value, input_index, lines):
    recorded_lines = (lines,) if isinstance(lines, int) else tuple(lines)
    observations.setdefault(key, []).append((value, input_index, recorded_lines))


def _literal(node):
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def _literal_lines(node):
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        return tuple(item.lineno for item in node.elts)
    return (node.lineno,)


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
    if not isinstance(value, (list, tuple)) or not value or not all(isinstance(item, str) and item for item in value):
        return None
    return list(value)


def _immutable_anchor(value):
    """Accept ``repo@40-hex-SHA/path:Lx-Ly`` immutable source anchors only."""

    repository, marker, revision_path = value.rpartition("@")
    if not marker or "@" in repository or not _anchor_ascii(repository):
        return False
    revision, separator, location = revision_path.partition("/")
    if not separator or len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        return False
    source_path, line_marker, line_range = location.rpartition(":")
    if not line_marker or source_path.startswith("/") or "\\" in source_path or not _anchor_ascii(source_path):
        return False
    components = source_path.split("/")
    if any(component in ("", ".", "..") for component in components):
        return False
    first, hyphen, last = line_range.partition("-")
    if not hyphen or first.count("L") != 1 or last.count("L") != 1 or not first.startswith("L") or not last.startswith("L"):
        return False
    if not _line_number(first[1:]) or not _line_number(last[1:]):
        return False
    return len(first[1:]) < len(last[1:]) or len(first[1:]) == len(last[1:]) and first[1:] <= last[1:]


def _anchor_ascii(value):
    return bool(value) and all(unicodedata.category(character).startswith("C") is False and character in ANCHOR_ASCII for character in value)


def _line_number(value):
    return bool(value) and value[0] != "0" and all("0" <= character <= "9" for character in value)


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
    call_clues = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in CLUE_FAMILIES:
            call_clues.setdefault(name, []).append(node.func.lineno)
    if call_clues:
        _add(observations, "construction.parameter_signature", sorted(call_clues), input_index, tuple(line for lines in call_clues.values() for line in lines))
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
                _add(observations, "rsa.same_plaintext", value, input_index, _literal_lines(value_node))
            elif isinstance(value, int) and not isinstance(value, bool):
                if lowered in ("e", "public_exponent"):
                    _add(observations, "rsa.public_exponent", value, input_index, _literal_lines(value_node))
                elif lowered in ("n", "modulus"):
                    _add(observations, "rsa.modulus", value, input_index, _literal_lines(value_node))
            elif isinstance(value, str) and lowered in ("scheme", "signature_scheme") and value.lower() == "ecdsa":
                _add(observations, "signature.scheme", "ecdsa", input_index, _literal_lines(value_node))
            values = _integer_list(value)
            if values is not None:
                if lowered in ("moduli", "ns"):
                    _add(observations, "rsa.moduli", values, input_index, _literal_lines(value_node))
                elif lowered in ("ciphertexts", "cts"):
                    _add(observations, "rsa.ciphertexts", values, input_index, _literal_lines(value_node))
            strings = _string_list(value)
            if strings is not None and lowered == "source_anchors" and all(_immutable_anchor(item) for item in strings):
                _add(observations, "construction.source_anchors", strings, input_index, _literal_lines(value_node))
            samples = _signature_samples(value)
            if samples is not None and lowered in ("signatures", "sigs"):
                _add(observations, "signature.samples", samples, input_index, _literal_lines(value_node))


def _extract_transcript(text, input_index, observations):
    moduli = []
    ciphertexts = []
    exponents = []
    for match in HEX_INTEGER.finditer(text):
        label = match.group(1)
        value = int(match.group(2), 16)
        line = _line(text, match.start())
        if label in ("n", "modulus"):
            moduli.append((value, line))
        elif label in ("e", "public_exponent"):
            exponents.append((value, line))
        else:
            ciphertexts.append((value, line))
    if len(moduli) == 1:
        _add(observations, "rsa.modulus", moduli[0][0], input_index, (moduli[0][1],))
    elif moduli:
        _add(observations, "rsa.moduli", [value for value, _line_number in moduli], input_index, tuple(line for _value, line in moduli))
    if ciphertexts:
        _add(observations, "rsa.ciphertexts", [value for value, _line_number in ciphertexts], input_index, tuple(line for _value, line in ciphertexts))
    if exponents:
        exponent_values = [value for value, _line_number in exponents]
        exponent_lines = tuple(line for _value, line in exponents)
        if all(value == exponent_values[0] for value in exponent_values):
            _add(observations, "rsa.public_exponent", exponent_values[0], input_index, exponent_lines)
        else:
            _add(observations, "rsa.public_exponents", exponent_values, input_index, exponent_lines)


def _extract_clues(text, input_index, observations):
    clues = {}
    for match in CLUE_TOKEN.finditer(text):
        clues.setdefault(match.group(1), []).append(_line(text, match.start(1)))
    if clues:
        _add(observations, "construction.parameter_signature", sorted(clues), input_index, tuple(line for lines in clues.values() for line in lines))


def _extract_text(text, input_index, observations):
    paper_matches = []
    for match in DOI_URL.finditer(text):
        identifier = _doi_identifier(text, match) if _url_started(text, match.start()) else None
        if identifier is not None:
            paper_matches.append(("doi:{0}".format(identifier), _line(text, match.end())))
    paper_matches.extend(("eprint:{0}".format(match.group(1)), _line(text, match.start(1))) for match in EPRINT_URL.finditer(text) if _url_started(text, match.start()) and _eprint_terminated(text, match.end()))
    if paper_matches:
        _add(observations, "construction.paper_ids", sorted(set(value for value, _line_number in paper_matches)), input_index, tuple(line for _value, line in paper_matches))
    _extract_clues(text, input_index, observations)


def _url_started(text, start):
    return start == 0 or text[start - 1].isspace() or text[start - 1] in URL_OPENERS


def _doi_identifier(text, match):
    end = match.end()
    while end < len(text) and not text[end].isspace() and text[end] not in DOI_TOKEN_STOPPERS:
        end += 1
    candidate = text[match.end():end]
    preceding = text[match.start() - 1] if match.start() else ""
    prose_context = preceding.isspace() or preceding == "("
    if candidate.endswith((",", ".")):
        if not prose_context:
            return None
        candidate = candidate[:-1]
    if candidate.endswith(")") and preceding == "(" and _doi_parentheses_balanced(candidate[:-1]):
        candidate = candidate[:-1]
    if DOI_IDENTIFIER.fullmatch(candidate) is None or not _doi_parentheses_balanced(candidate):
        return None
    return candidate


def _doi_parentheses_balanced(identifier):
    depth = 0
    for character in identifier:
        if character == "(":
            depth += 1
        elif character == ")":
            if depth == 0:
                return False
            depth -= 1
    return depth == 0


def _eprint_terminated(text, end):
    if end == len(text) or text[end].isspace() or text[end] in URL_CLOSERS:
        return True
    return text[end] in ".,;!?" and (end + 1 == len(text) or text[end + 1].isspace() or text[end + 1] in URL_CLOSERS)


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
