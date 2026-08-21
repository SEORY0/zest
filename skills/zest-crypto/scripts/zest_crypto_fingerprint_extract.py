# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Extract source-backed observations for Zest crypto fingerprints."""

import ast
import re

from zest_crypto_input import MAX_AST_NODES, InputBoundaryError
from zest_crypto_source import is_canonical_source_anchor


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
URL_OPENERS = frozenset(("\"", "'", "<", "(", "[", "{"))
URL_CLOSERS = frozenset(("\"", "'", "<", ">", ")", "]", "}"))
DOI_TOKEN_STOPPERS = frozenset(("\"", "'", "<", ">", "[", "]", "{", "}"))


def _line(text, offset):
    return text.count("\n", 0, offset) + 1


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
    return is_canonical_source_anchor(value)


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
    nodes = []
    for node in ast.walk(tree):
        nodes.append(node)
        if len(nodes) > MAX_AST_NODES:
            raise InputBoundaryError("$[{0}]".format(input_index + 1), "input-too-complex")
    call_clues = {}
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in CLUE_FAMILIES:
            call_clues.setdefault(name, []).append(node.func.lineno)
    if call_clues:
        _add(observations, "construction.parameter_signature", sorted(call_clues), input_index, tuple(line for lines in call_clues.values() for line in lines))
    for node in nodes:
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
