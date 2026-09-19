"""Deterministic ingress and egress data-loss-prevention helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .models import DataLabel


EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
SECRET = re.compile(
    r"\b(?:sk|api|token|secret)[-_][A-Za-z0-9_-]{8,}\b|"
    r"\bBearer\s+[A-Za-z0-9._~-]{12,}\b",
    re.I,
)
PHONE = re.compile(r"(?<!\d)(?:\+?\d[\d .()-]{8,}\d)(?!\d)")
CONFIDENTIAL_TERMS = re.compile(
    r"\b(?:crm\s+extract|customer\s+(?:data|record|list|database)s?|client\s+list|"
    r"payroll|salary\s+band|account\s+statement|internal\s+only|confidential)\b",
    re.I,
)


@dataclass(frozen=True, slots=True)
class DLPResult:
    labels: frozenset[DataLabel]
    redacted: str
    match_count: int


class DLPGuard:
    def scan_text(self, text: str) -> DLPResult:
        labels: set[DataLabel] = set()
        match_count = 0

        def redact(pattern: re.Pattern[str], label: DataLabel, value: str) -> str:
            nonlocal match_count

            def replace(_: re.Match[str]) -> str:
                nonlocal match_count
                match_count += 1
                labels.add(label)
                return f"[REDACTED:{label.value.upper()}]"

            return pattern.sub(replace, value)

        redacted = redact(SECRET, DataLabel.SECRET, text)
        redacted = redact(EMAIL, DataLabel.PII, redacted)
        redacted = redact(PHONE, DataLabel.PII, redacted)
        if not labels:
            labels.add(DataLabel.PUBLIC)
        return DLPResult(frozenset(labels), redacted, match_count)

    def labels_for_value(self, value: Any, *, ignored_keys: Iterable[str] = ()) -> frozenset[DataLabel]:
        labels: set[DataLabel] = set()
        ignored = frozenset(ignored_keys)
        if isinstance(value, str):
            labels.update(self.scan_text(value).labels)
            # Business-sensitivity wording classifies data the agent is *moving*, so it
            # is applied at egress only. The same words in an inbound public webpage
            # describe data, they are not data, and labelling them would false-positive.
            if CONFIDENTIAL_TERMS.search(value):
                labels.add(DataLabel.CONFIDENTIAL)
        elif isinstance(value, Mapping):
            for key, item in value.items():
                if str(key) not in ignored:
                    labels.update(self.labels_for_value(item, ignored_keys=ignored))
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                labels.update(self.labels_for_value(item, ignored_keys=ignored))
        if len(labels) > 1:
            labels.discard(DataLabel.PUBLIC)
        return frozenset(labels or {DataLabel.PUBLIC})

    def redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.scan_text(value).redacted
        if isinstance(value, Mapping):
            return {key: self.redact_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_value(item) for item in value)
        return value
