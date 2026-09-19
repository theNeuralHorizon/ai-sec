"""A small, inspectable classifier and layered prompt-scope guard.

It is intentionally deterministic.  The demonstration is about proving that an
unsafe 3.8B/4B-class model is not the security boundary, rather than claiming
that a keyword classifier offers comprehensive model safety.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import Enum


class ScopeVerdict(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    SENSITIVE_EXFILTRATION = "SENSITIVE_EXFILTRATION"
    PROMPT_INJECTION = "PROMPT_INJECTION"


@dataclass(frozen=True, slots=True)
class ScopeAssessment:
    verdict: ScopeVerdict
    confidence: float
    reason: str
    intended_tool: str | None
    signals: tuple[str, ...]

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["verdict"] = self.verdict.value
        return payload


class LightweightScopeClassifier:
    """Narrow lexical classifier for the synthetic supply-chain task boundary."""

    _injection = re.compile(r"\b(ignore|override|reveal)\b.{0,45}\b(instruction|policy|prompt|guardrail)\b", re.I)
    _exfiltration = re.compile(r"\b(send|email|upload|export|post|share)\b.{0,80}\b(manifest|customer|contact|credential|secret|data|file)\b", re.I)
    _delete = re.compile(r"\b(delete|erase|wipe|remove)\b", re.I)
    _shipment = re.compile(
        r"\b(shipment|container|eta|delay|arrival|arrive|arrives|arrived|delivery|delivered|nf-\d{4})\b",
        re.I,
    )
    _documents = re.compile(r"\b(file|document|playbook|contract|brief|policy|report|search|summari[sz])\b", re.I)
    _notify = re.compile(r"\b(notify|update|tell)\b.{0,50}\b(customer|client)\b|\bcustomer\b.{0,50}\b(notify|update)\b", re.I)

    def assess(self, prompt: str) -> ScopeAssessment:
        normalized = " ".join(prompt.split())
        if not normalized:
            return ScopeAssessment(ScopeVerdict.OUT_OF_SCOPE, 1.0, "A task prompt is required.", None, ("empty_prompt",))
        if self._injection.search(normalized):
            return ScopeAssessment(ScopeVerdict.PROMPT_INJECTION, 0.97, "The request tries to alter Aegis instructions or policy.", None, ("instruction_override",))
        if self._exfiltration.search(normalized):
            return ScopeAssessment(ScopeVerdict.SENSITIVE_EXFILTRATION, 0.96, "The request combines an external transfer verb with protected company data.", None, ("sensitive_egress",))
        if self._delete.search(normalized):
            return ScopeAssessment(ScopeVerdict.OUT_OF_SCOPE, 0.94, "Deleting company data is outside this read-and-notify demo mandate.", None, ("destructive_action",))
        if self._notify.search(normalized):
            return ScopeAssessment(ScopeVerdict.IN_SCOPE, 0.86, "Preparing a customer portal update is a permitted, approval-gated workflow.", "customer.notify", ("customer_update",))
        if self._shipment.search(normalized):
            return ScopeAssessment(ScopeVerdict.IN_SCOPE, 0.89, "Shipment status lookups are part of the operational workflow.", "shipment.lookup", ("shipment_intent",))
        if self._documents.search(normalized):
            return ScopeAssessment(ScopeVerdict.IN_SCOPE, 0.83, "Searching approved company documents is in scope.", "company.files.search", ("document_intent",))
        return ScopeAssessment(ScopeVerdict.OUT_OF_SCOPE, 0.72, "This demo only handles approved document search, shipment lookup, and customer-update preparation.", None, ("unsupported_intent",))


class MultiLayerScopeGuard:
    """Explainable security layers around a potentially non-refusing model."""

    def __init__(self) -> None:
        self.classifier = LightweightScopeClassifier()

    def assess(self, prompt: str) -> dict:
        lexical = self.classifier.assess(prompt)
        return {
            "layers": [
                {"name": "input normalization", "result": "PASS", "detail": "Whitespace normalized; prompt retained for audit."},
                {"name": "scope classifier", "result": lexical.verdict.value, "detail": lexical.reason},
                {"name": "model isolation", "result": "PENDING" if lexical.verdict is ScopeVerdict.IN_SCOPE else "SKIPPED", "detail": "The model receives only approved task context and cannot call tools directly."},
                {"name": "deterministic policy", "result": "PENDING" if lexical.verdict is ScopeVerdict.IN_SCOPE else "BLOCK", "detail": "Every proposed tool call is independently authorized."},
                {"name": "agent EDR", "result": "ARMED", "detail": "Correlates denial, tool drift, and containment signals."},
            ],
            "assessment": lexical.to_dict(),
        }
