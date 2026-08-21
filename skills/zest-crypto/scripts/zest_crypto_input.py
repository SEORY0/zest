# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Bounded filesystem and JSON input boundaries for Zest crypto scripts."""

from __future__ import annotations

import errno
import json
import math
import os
import stat
from typing import Any, Dict, List, Sequence, Tuple


MAX_INPUT_BYTES = 1_000_000
MAX_AST_NODES = 50_000
MAX_JSON_INTEGER_DIGITS = 4096
MAX_JSON_DEPTH = 256
MAX_JSON_NODES = 50_000


class InputBoundaryError(Exception):
    """Stable structured error for untrusted input boundaries."""

    def __init__(self, path: str, code: str) -> None:
        self.path = path
        self.code = code


def read_bounded_text(raw_path: str, issue_path: str, os_module: Any = os) -> str:
    content = read_bounded_bytes(raw_path, issue_path, os_module)
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InputBoundaryError(issue_path, "input-undecodable") from error


def read_bounded_bytes(raw_path: str, issue_path: str, os_module: Any = os) -> bytes:
    flags = os_module.O_RDONLY | getattr(os_module, "O_CLOEXEC", 0) | getattr(os_module, "O_NONBLOCK", 0)
    nofollow = getattr(os_module, "O_NOFOLLOW", None)
    descriptor = None
    try:
        original = os_module.lstat(raw_path)
        if stat.S_ISLNK(original.st_mode):
            raise InputBoundaryError(issue_path, "input-symlink")
        if not stat.S_ISREG(original.st_mode):
            raise InputBoundaryError(issue_path, "input-not-file")
        if original.st_size > MAX_INPUT_BYTES:
            raise InputBoundaryError(issue_path, "input-too-large")
        if nofollow is not None:
            flags |= nofollow
        descriptor = os_module.open(raw_path, flags)
        opened = os_module.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise InputBoundaryError(issue_path, "input-not-file")
        if original.st_dev != opened.st_dev or original.st_ino != opened.st_ino:
            raise InputBoundaryError(issue_path, "input-unreadable")
        chunks: List[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining > 0:
            chunk = os_module.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > MAX_INPUT_BYTES:
            raise InputBoundaryError(issue_path, "input-too-large")
        return content
    except InputBoundaryError:
        raise
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise InputBoundaryError(issue_path, "input-symlink") from error
        raise InputBoundaryError(issue_path, "input-unreadable") from error
    finally:
        if descriptor is not None:
            os_module.close(descriptor)


def loads_bounded_json(contents: str) -> Any:
    _check_json_depth(contents)
    value = json.loads(
        contents,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_non_standard_json_constant,
        parse_float=_parse_finite_json_float,
        parse_int=_parse_json_integer,
    )
    _check_json_node_count(value)
    return value


def _reject_non_standard_json_constant(value: str) -> None:
    raise json.JSONDecodeError("non-standard JSON constant: {0}".format(value), value, 0)


def _parse_finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise json.JSONDecodeError("non-finite JSON number: {0}".format(value), value, 0)
    return number


def _parse_json_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise json.JSONDecodeError("JSON integer has too many digits", value, 0)
    try:
        return int(value)
    except ValueError as error:
        raise json.JSONDecodeError("invalid JSON integer", value, 0) from error


def _unique_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise json.JSONDecodeError("duplicate JSON object key: {0}".format(key), key, 0)
        result[key] = value
    return result


def _check_json_depth(contents: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in contents:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise RecursionError("JSON nesting limit exceeded")
        elif character in "]}":
            depth -= 1


def _check_json_node_count(value: Any) -> None:
    count = 0
    stack = [value]
    while stack:
        item = stack.pop()
        count += 1
        if count > MAX_JSON_NODES:
            raise InputBoundaryError("$", "input-too-complex")
        if isinstance(item, list):
            stack.extend(item)
            continue
        if isinstance(item, dict):
            stack.extend(item.values())
