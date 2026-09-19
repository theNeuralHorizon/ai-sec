"""Typed contracts shared across Aegis security boundaries."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class TrustLabel(StrEnum):
    SYSTEM_POLICY = "SYSTEM_POLICY"
    USER_REQUEST = "USER_REQUEST"
    TRUSTED_INTERNAL = "TRUSTED_INTERNAL"
    EXTERNAL_EVIDENCE = "EXTERNAL_EVIDENCE"
    SUSPICIOUS_EXTERNAL = "SUSPICIOUS_EXTERNAL"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"


class DataLabel(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    SECRET = "secret"


class ActionClass(StrEnum):
    READ = "read"
    WRITE = "write"
    OUTBOUND = "outbound"
    DESTRUCTIVE = "destructive"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_WITH_REDACTION = "ALLOW_WITH_REDACTION"
    ALLOW_READ_ONLY = "ALLOW_READ_ONLY"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    QUARANTINE_SESSION = "QUARANTINE_SESSION"
    DENY = "DENY"


class SessionState(StrEnum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    CONTAINED = "CONTAINED"
    REVIEWED = "REVIEWED"


@dataclass(frozen=True, slots=True)
class TaskMandate:
    task_id: str
    agent_id: str
    human_owner: str
    purpose: str
    allowed_tools: frozenset[str]
    forbidden_tools: frozenset[str] = frozenset()
    data_clearance: frozenset[DataLabel] = frozenset({DataLabel.PUBLIC})
    approved_destinations: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ContextSegment:
    segment_id: str
    text: str
    trust: TrustLabel
    location: str
    source_id: str
    transformations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    rule_id: str
    category: str
    severity: str
    confidence: float
    location: str
    evidence: str


@dataclass(slots=True)
class ContextEnvelope:
    source_id: str
    source_type: str
    requested_url: str
    final_url: str
    content_hash: str
    source_trust: TrustLabel
    evidence: list[ContextSegment] = field(default_factory=list)
    quarantined: list[ContextSegment] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    data_labels: set[DataLabel] = field(default_factory=lambda: {DataLabel.PUBLIC})
    risk_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ToolRequest:
    run_id: str
    tool_name: str
    action_class: ActionClass
    arguments: dict[str, Any]
    destination: str | None = None
    data_labels: frozenset[DataLabel] = frozenset({DataLabel.PUBLIC})
    source_trust: TrustLabel = TrustLabel.EXTERNAL_EVIDENCE
    influenced_by: tuple[str, ...] = ()
    approval_granted: bool = False


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: Decision
    rule_id: str
    reason: str
    policy_version: str = "aegis-policy-0.1"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    run_id: str
    event_type: str
    outcome: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    source_id: str | None = None
    tool_name: str | None = None
    destination: str | None = None
    policy_rule_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

