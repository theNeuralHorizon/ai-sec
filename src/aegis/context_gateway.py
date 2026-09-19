"""Secure Context Gateway for deterministic local HTML inspection."""

from __future__ import annotations

import base64
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlparse

from .dlp import DLPGuard
from .models import ContextEnvelope, ContextSegment, DataLabel, Finding, TrustLabel


ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
INSTRUCTION_PATTERNS = (
    # Qualifiers repeat in real payloads ("ignore previous *user* instructions"), so the
    # qualifier group has to be repeatable; a single slot silently misses the commonest phrasing.
    re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?"
        r"(?:the\s+|your\s+|these\s+|those\s+|my\s+)?"
        r"(?:(?:previous|prior|preceding|above|earlier|user|system|developer)\s+){1,3}"
        r"instructions?\b",
        re.I,
    ),
    re.compile(r"\b(?:new|updated)\s+(?:system|developer)\s+(?:message|instructions?)\b", re.I),
    re.compile(r"\b(?:do not|never)\s+(?:tell|show|reveal)\s+(?:the\s+)?user\b", re.I),
    # Must name an authority role. A bare "act as" matches ordinary product copy
    # ("can act as a desktop replacement"), which is the shape this detector reads all day.
    re.compile(
        r"\b(?:act|respond|behave)\s+as\s+(?:a\s+|an\s+|the\s+)?"
        r"(?:system|admin|administrator|developer|assistant|agent|operator|root|superuser)\b",
        re.I,
    ),
)
# The object has to be qualified. A bare "data" or "customer" turns "send your data to
# the cloud" into a critical exfiltration finding on a normal marketing page.
EXFILTRATION_PATTERN = re.compile(
    r"\b(?:send|email|upload|post|forward|transmit|exfiltrat\w*)\b.{0,100}"
    r"\b(?:secrets?|tokens?|credentials?|passwords?|api\s*keys?|browsing\s+history|"
    r"system\s+prompt|(?:customer|client|user|personal|private|confidential|crm)\s+"
    r"(?:data|records?|information|list|extract))\b",
    re.I | re.S,
)
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

    def __init__(self) -> None:
        self.dlp = DLPGuard()

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

            dlp_result = self.dlp.scan_text(original)
            data_labels.update(dlp_result.labels)
            if dlp_result.labels != frozenset({DataLabel.PUBLIC}):
                data_labels.discard(DataLabel.PUBLIC)
            safe_text = dlp_result.redacted

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
            if dlp_result.match_count:
                segment_transformations = (*segment_transformations, "dlp-redacted")

            if suspicious:
                segment = ContextSegment(
                    segment_id,
                    safe_text,
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
                            safe_text,
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
                            safe_text,
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
                            safe_text,
                        )
                    )
                    risk_score += 45
            elif not raw.hidden:
                evidence.append(
                    ContextSegment(
                        segment_id,
                        safe_text,
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
                        safe_text,
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
