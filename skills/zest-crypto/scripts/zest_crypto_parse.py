# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Strict JSON-to-domain parsing for Zest crypto fingerprints and AttackCards.

JSON decoding belongs to the command boundary.  The public parsing functions
accept already-decoded values so callers cannot accidentally decode nested JSON
or turn malformed boundary data into trusted domain objects.
"""

from __future__ import annotations

from zest_crypto_parse_catalog import (
    parse_catalog as parse_catalog,
    validate_catalog as validate_catalog,
)
from zest_crypto_parse_fingerprint import parse_fingerprint as parse_fingerprint
from zest_crypto_parse_values import (
    CANONICAL_PROVENANCE_SCHEMA_VERSIONS as CANONICAL_PROVENANCE_SCHEMA_VERSIONS,
    CARD_ID_RE as CARD_ID_RE,
    CONTAINS_VALUE_TYPES as CONTAINS_VALUE_TYPES,
    FACT_VALUE_TYPES as FACT_VALUE_TYPES,
    FACT_VALUE_TYPES_BY_SCHEMA as FACT_VALUE_TYPES_BY_SCHEMA,
    GIT_SHA_RE as GIT_SHA_RE,
    LENGTH_VALUE_TYPES as LENGTH_VALUE_TYPES,
    NUMERIC_VALUE_TYPES as NUMERIC_VALUE_TYPES,
    READ_ONLY_SCHEMA_VERSIONS as READ_ONLY_SCHEMA_VERSIONS,
    SCHEMA_VERSION as SCHEMA_VERSION,
    SHA256_RE as SHA256_RE,
    SUPPORTED_SCHEMA_VERSIONS as SUPPORTED_SCHEMA_VERSIONS,
    V1_FACT_VALUE_TYPES as V1_FACT_VALUE_TYPES,
    V2_FACT_VALUE_TYPES as V2_FACT_VALUE_TYPES,
    VALUE_TYPES as VALUE_TYPES,
)
