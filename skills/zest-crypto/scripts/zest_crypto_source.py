# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Canonical URL, source-range, and immutable-anchor validation."""

import re
from urllib.parse import unquote, urlsplit


CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
PERCENT_RE = re.compile(r"%([0-9A-Fa-f]{2})")
SOURCE_LINES_RE = re.compile(r"L([1-9][0-9]*)-L([1-9][0-9]*)")
SHA_RE = re.compile(r"[0-9a-f]{40}")
HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
REPOSITORY_COMPONENT_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
SOURCE_COMPONENT_RE = re.compile(r"(?:[A-Za-z0-9._~!$&'()+,;=@-]|%[0-9A-F]{2})+")
ASCII_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _canonical_percent_encoding(value):
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        match = PERCENT_RE.match(value, index)
        if match is None or match.group(1) != match.group(1).upper():
            return False
        decoded = chr(int(match.group(1), 16))
        if decoded in "/\\" or decoded in ASCII_UNRESERVED or ord(decoded) <= 0x1F or ord(decoded) == 0x7F:
            return False
        index += 3
    return True


def _canonical_path(path, allow_empty=False, source=False):
    if not path:
        return allow_empty
    if "\\" in path or " " in path or CONTROL_RE.search(path) or not path.isascii():
        return False
    if not _canonical_percent_encoding(path):
        return False
    components = path.split("/")
    if path.startswith("/"):
        components = components[1:]
    if any(not component for component in components):
        return False
    try:
        decoded = [unquote(component, errors="strict") for component in components]
    except (UnicodeDecodeError, ValueError):
        return False
    if any(component in (".", "..") for component in decoded):
        return False
    return not source or all(SOURCE_COMPONENT_RE.fullmatch(component) for component in components)


def is_canonical_https_url(value, repository=False):
    """Return whether *value* is a canonical, unambiguous HTTPS URL."""

    if not isinstance(value, str) or not value or not value.isascii():
        return False
    if CONTROL_RE.search(value) or "\\" in value:
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.netloc or parsed.username is not None or parsed.password is not None:
        return False
    if "%" in parsed.netloc:
        return False
    hostname = parsed.hostname
    if hostname is None or hostname != hostname.lower() or not HOST_RE.fullmatch(hostname):
        return False
    if port is not None or parsed.netloc != hostname:
        return False
    if not _canonical_path(parsed.path, allow_empty=not repository):
        return False
    if parsed.query or (parsed.fragment and not is_canonical_source_lines(parsed.fragment)):
        return False
    if repository:
        if parsed.fragment:
            return False
        components = parsed.path.lstrip("/").split("/")
        if len(components) != 2 or any(REPOSITORY_COMPONENT_RE.fullmatch(component) is None for component in components):
            return False
    return True


def is_canonical_source_lines(value):
    if not isinstance(value, str):
        return False
    match = SOURCE_LINES_RE.fullmatch(value)
    return match is not None and int(match.group(1)) <= int(match.group(2))


def is_canonical_source_anchor(value):
    """Return whether *value* is ``host/owner/repo@sha/path:Lx-Ly``."""

    if not isinstance(value, str) or not value.isascii() or CONTROL_RE.search(value):
        return False
    repository, marker, revision_path = value.rpartition("@")
    if not marker or "@" in repository:
        return False
    revision, separator, location = revision_path.partition("/")
    if not separator or SHA_RE.fullmatch(revision) is None:
        return False
    source_path, line_marker, source_lines = location.rpartition(":")
    if not line_marker or source_path.startswith("/") or not _canonical_path(source_path, source=True):
        return False
    if not is_canonical_source_lines(source_lines):
        return False
    components = repository.split("/")
    if len(components) != 3:
        return False
    host, owner, repo = components
    if not HOST_RE.fullmatch(host) or host != host.lower() or "." not in host:
        return False
    return REPOSITORY_COMPONENT_RE.fullmatch(owner) is not None and REPOSITORY_COMPONENT_RE.fullmatch(repo) is not None
