# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""Frozen domain values for the Zest crypto AttackCard boundary.

This module deliberately uses ``typing.Optional`` instead of ``X | None`` so
the published helpers remain importable on Python 3.8.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, NewType, Optional, Tuple, Union


JsonValue = Any
FactKey = NewType("FactKey", str)
FactId = NewType("FactId", str)
CardId = NewType("CardId", str)
FactValue = Union[bool, int, float, str, Tuple[int, ...], Tuple[str, ...]]


class FactStatus(str, Enum):
    OBSERVED = "observed"
    DERIVED = "derived"
    INFERRED = "inferred"


class Truth(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class CardState(str, Enum):
    ELIGIBLE = "eligible"
    BLOCKED = "blocked"
    REJECTED = "rejected"


class CostClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ORACLE_BOUND = "oracle-bound"


class Operator(str, Enum):
    EXISTS = "exists"
    EQ = "eq"
    NEQ = "neq"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    IN = "in"
    CONTAINS = "contains"
    LEN_EQ = "len_eq"
    LEN_GTE = "len_gte"


@dataclass(frozen=True)
class ParseError(Exception):
    """A user-facing JSON boundary error with a stable location and code."""

    path: str
    code: str
    detail: str

    def __str__(self) -> str:
        return "{0}: {1} ({2})".format(self.path, self.code, self.detail)


@dataclass(frozen=True)
class CatalogIssue:
    path: str
    code: str
    detail: Optional[str] = None


@dataclass(frozen=True)
class Evidence:
    input_id: Optional[str]
    locator: Optional[str]
    source_fact_ids: Tuple[FactId, ...]
    rationale: Optional[str]


@dataclass(frozen=True)
class InputArtifact:
    id: str
    path: str
    sha256: str
    media_type: str


@dataclass(frozen=True)
class Capability:
    command: str
    available: bool
    version: Optional[str]


@dataclass(frozen=True)
class Constraints:
    network: str
    max_seconds: Optional[int]
    max_memory_mb: Optional[int]
    max_oracle_queries: Optional[int]


@dataclass(frozen=True)
class Fact:
    id: FactId
    key: FactKey
    value: FactValue
    status: FactStatus
    evidence: Evidence


@dataclass(frozen=True)
class Fingerprint:
    schema_version: int
    case_id: str
    inputs: Tuple[InputArtifact, ...]
    facts: Tuple[Fact, ...]
    capabilities: Tuple[Capability, ...]
    constraints: Constraints


@dataclass(frozen=True)
class Condition:
    fact: Optional[FactKey]
    op: Optional[Operator]
    value: Optional[FactValue]
    all_of: Tuple["Condition", ...]
    any_of: Tuple["Condition", ...]
    not_: Optional["Condition"]


@dataclass(frozen=True)
class Rule:
    id: str
    when: Condition
    reason: str


@dataclass(frozen=True)
class Signal:
    id: str
    when: Condition
    weight: int
    reason: str


@dataclass(frozen=True)
class NegativeMatch:
    id: str
    when: Condition
    reason: str
    unknown_policy: str


@dataclass(frozen=True)
class Cost:
    cost_class: CostClass
    notes: str


@dataclass(frozen=True)
class ToolRequirement:
    command: str
    required: bool
    packages: Tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class Citation:
    kind: str
    paper_id: str
    title: str
    url: str
    year: int
    section: str
    assumptions: Tuple[str, ...]
    verified_on: str


@dataclass(frozen=True)
class PinnedExample:
    challenge_id: str
    event: str
    year: int
    repo_url: str
    repo_sha: str
    source_path: str
    source_lines: str
    inference_level: str


@dataclass(frozen=True)
class CheapProbe:
    id: str
    instruction: str
    max_seconds: int
    produces_facts: Tuple[FactKey, ...]


@dataclass(frozen=True)
class ProcedureStep:
    id: str
    instruction: str


@dataclass(frozen=True)
class VerificationStep:
    kind: str
    instruction: str


@dataclass(frozen=True)
class AttackCard:
    id: CardId
    version: int
    canonical_family_id: str
    signals: Tuple[Signal, ...]
    requires: Tuple[Rule, ...]
    rejects: Tuple[Rule, ...]
    negative_matches: Tuple[NegativeMatch, ...]
    expected_cost: Cost
    tooling: Tuple[ToolRequirement, ...]
    template: Optional[str]
    title: str
    family_aliases: Tuple[str, ...]
    summary: str
    parameter_signature: Tuple[FactKey, ...]
    cheap_probes: Tuple[CheapProbe, ...]
    procedure: Tuple[ProcedureStep, ...]
    citations: Tuple[Citation, ...]
    examples: Tuple[PinnedExample, ...]
    verification: Tuple[VerificationStep, ...]


FactIndex = Dict[FactKey, Fact]
