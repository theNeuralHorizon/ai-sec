"""Secure Context Gateway for deterministic local HTML inspection."""

from __future__ import annotations

import base64
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlparse

from .models import ContextEnvelope, ContextSegment, DataLabel, Finding, TrustLabel


ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|user|system)\s+instructions?\b", re.I),
    re.compile(r"\b(?:new|updated)\s+(?:system|developer)\s+(?:message|instructions?)\b", re.I),
    re.compile(r"\b(?:do not|never)\s+(?:tell|show|reveal)\s+(?:the\s+)?user\b", re.I),
    re.compile(r"\b(?:act|respond|behave)\s+as\b", re.I),
)
EXFILTRATION_PATTERN = re.compile(
    r"\b(?:send|email|upload|post|forward|exfiltrat\w*)\b.{0,100}"
    r"\b(?:secret|token|credential|history|customer|private|system prompt|data)\b",
    re.I | re.S,
)
SECRET_PATTERN = re.compile(r"\b(?:sk|api|token)[-_][A-Za-z0-9_-]{8,}\b", re.I)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"})


@dataclass(frozen=True, slots=True)
class RawSegment:
    text: str
    location: str
    hidden: bool
    quoted: bool
    transformations: tuple[str, ...] = ()


def _style_is_hidden(style: str) -> bool:
    compact = re.sub(r"\s+", "", style.lower())
    return any(
        marker in compact
        for marker in (
            "display:none",
            "visibility:hidden",
            "opacity:0",
            "font-size:0",
            "left:-9999",
            "top:-9999",
            "height:0;overflow:hidden",
        )
    )


class _CaptureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.segments: list[RawSegment] = []
        self._stack: list[tuple[str, bool, bool]] = []
        self._node_counter = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr_map = {name.lower(): value or "" for name, value in attrs}
        inherited_hidden = self._stack[-1][1] if self._stack else False
        inherited_quoted = self._stack[-1][2] if self._stack else False
        hidden = inherited_hidden or tag in {"script", "style", "template", "noscript"}
        hidden = hidden or "hidden" in attr_map or _style_is_hidden(attr_map.get("style", ""))
        quoted = inherited_quoted or tag in {"code", "pre", "blockquote", "q"}
        for name, value in attr_map.items():
            if not value:
                continue
            if name in {"content", "alt", "title", "aria-label"} or name.startswith("data-"):
                self._append(value, f"html:{tag}[@{name}]", True, quoted)
        if tag not in VOID_TAGS:
            self._stack.append((tag, hidden, quoted))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == tag.lower():
                del self._stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if not data.strip():
            return
        hidden = self._stack[-1][1] if self._stack else False
        quoted = self._stack[-1][2] if self._stack else False
        tag = self._stack[-1][0] if self._stack else "document"
        self._append(data, f"html:{tag}[{self._node_counter}]", hidden, quoted)

    def handle_comment(self, data: str) -> None:
        self._append(data, f"html:comment[{self._node_counter}]", True, False)

    def _append(self, text: str, location: str, hidden: bool, quoted: bool) -> None:
        self._node_counter += 1
        self.segments.append(RawSegment(text.strip(), location, hidden, quoted))


class ContextGateway:
    """Turn an HTML artifact into a provenance-aware context envelope."""

    def analyze_html(self, *, source_id: str, url: str, html: str) -> ContextEnvelope:
        self._validate_url(url)
        parser = _CaptureParser()
        parser.feed(html)

        evidence: list[ContextSegment] = []
        quarantined: list[ContextSegment] = []
        findings: list[Finding] = []
        data_labels: set[DataLabel] = {DataLabel.PUBLIC}
        risk_score = 0

        for index, raw in enumerate(parser.segments, start=1):
            original = raw.text
            normalized, transformations = self._canonicalize(original)
            if not normalized:
                continue

            if SECRET_PATTERN.search(normalized):
                data_labels.add(DataLabel.SECRET)
            if EMAIL_PATTERN.search(normalized):
                data_labels.add(DataLabel.PII)

            decoded = self._decode_base64_probe(normalized)
            analyzed_text = f"{normalized}\n{decoded}" if decoded else normalized
            instruction_like = any(pattern.search(analyzed_text) for pattern in INSTRUCTION_PATTERNS)
            exfiltration = bool(EXFILTRATION_PATTERN.search(analyzed_text))
            zero_width = bool(ZERO_WIDTH.search(original))
            suspicious = exfiltration or (instruction_like and not raw.quoted) or (raw.hidden and instruction_like)

            segment_id = f"segment-{index}"
            segment_transformations = tuple((*raw.transformations, *transformations))
            if decoded:
                segment_transformations = (*segment_transformations, "base64-probe")

            if suspicious:
                segment = ContextSegment(
                    segment_id,
                    original,
                    TrustLabel.SUSPICIOUS_EXTERNAL,
                    raw.location,
                    source_id,
                    segment_transformations,
                )
                quarantined.append(segment)
                if raw.hidden:
                    findings.append(
                        self._finding(
                            len(findings) + 1,
                            "CG-HIDDEN-001",
                            "concealed_instruction",
                            "high",
                            0.95,
                            raw.location,
                            original,
                        )
                    )
                    risk_score += 45
                elif instruction_like:
                    findings.append(
                        self._finding(
                            len(findings) + 1,
                            "CG-INJ-001",
                            "instruction_override",
                            "high",
                            0.88,
                            raw.location,
                            original,
                        )
                    )
                    risk_score += 35
                if exfiltration:
                    findings.append(
                        self._finding(
                            len(findings) + 1,
                            "CG-EXFIL-001",
                            "data_exfiltration",
                            "critical",
                            0.96,
                            raw.location,
                            original,
                        )
                    )
                    risk_score += 45
            elif not raw.hidden:
                evidence.append(
                    ContextSegment(
                        segment_id,
                        original,
                        TrustLabel.EXTERNAL_EVIDENCE,
                        raw.location,
                        source_id,
                        segment_transformations,
                    )
                )

            if zero_width:
                findings.append(
                    self._finding(
                        len(findings) + 1,
                        "CG-UNICODE-001",
                        "invisible_character_obfuscation",
                        "medium",
                        0.85,
                        raw.location,
                        original,
                    )
                )
                risk_score += 20

        trust = TrustLabel.SUSPICIOUS_EXTERNAL if findings else TrustLabel.EXTERNAL_EVIDENCE
        return ContextEnvelope(
            source_id=source_id,
            source_type="web",
            requested_url=url,
            final_url=url,
            content_hash=f"sha256:{hashlib.sha256(html.encode('utf-8')).hexdigest()}",
            source_trust=trust,
            evidence=evidence,
            quarantined=quarantined,
            findings=findings,
            data_labels=data_labels,
            risk_score=min(risk_score, 100),
        )

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Only absolute HTTP(S) URLs can enter the context gateway")

    @staticmethod
    def _canonicalize(text: str) -> tuple[str, tuple[str, ...]]:
        transformations: list[str] = []
        normalized = unicodedata.normalize("NFKC", text)
        if normalized != text:
            transformations.append("unicode-nfkc")
        without_zero_width = ZERO_WIDTH.sub("", normalized)
        if without_zero_width != normalized:
            transformations.append("zero-width-removed")
        return " ".join(without_zero_width.split()), tuple(transformations)

    @staticmethod
    def _decode_base64_probe(text: str) -> str | None:
        match = BASE64_PATTERN.search(text)
        if not match:
            return None
        try:
            decoded = base64.b64decode(match.group(0), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        return decoded if decoded.isprintable() else None

    @staticmethod
    def _finding(
        number: int,
        rule_id: str,
        category: str,
        severity: str,
        confidence: float,
        location: str,
        evidence: str,
    ) -> Finding:
        return Finding(
            finding_id=f"finding-{number}",
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            location=location,
            evidence=evidence[:240],
        )
