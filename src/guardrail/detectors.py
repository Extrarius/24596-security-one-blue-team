"""Ordered keyword signals for the intentionally weak starter policy."""

from __future__ import annotations

from dataclasses import dataclass
from re import Pattern, compile as compile_pattern
from typing import Final, Protocol, Sequence, runtime_checkable

from common import Action, ReasonCode
from guardrail.abuse import is_generate_abuse_request
from guardrail.imminent_risk import is_imminent_safety_risk
from guardrail.normalization import normalize_text


@dataclass(frozen=True, slots=True)
class Signal:
    """A detector's proposed action and reason."""

    action: Action
    reason_code: ReasonCode


@runtime_checkable
class Detector(Protocol):
    """Structural interface implemented by starter signal detectors."""

    def detect(self, text: str) -> Signal | None:
        """Return one signal for a flattened input, or no signal."""


@dataclass(frozen=True, slots=True)
class KeywordRule:
    """One ordered policy concept and its literal trigger terms."""

    action: Action
    reason_code: ReasonCode
    keywords: tuple[str, ...]


DEFAULT_KEYWORD_RULES = (
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        ("ignore", "system prompt", "reveal", "secret"),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.MODERATION_EVASION,
        ("bypass", "evade", "avoid the filter"),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        ("threaten", "intimidate", "kill"),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        (
            "reporter identity",
            "private data",
            "home address",
            "who reported",
            "who submitted the complaint",
            "reporter name",
            "reporter's name",
            "unmask the reporter",
            "dox",
            "doxx",
            "another user's",
            "somebody else's",
        ),
    ),
)


PRIVATE_DATA_REQUEST_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\bwho\s+(?:reported|flagged|filed|submitted|made|sent)\b"
        r".{0,50}\b(?:report|complaint|case)?\b"
    ),
    compile_pattern(
        r"\b(?:identify|unmask|reveal|name|find)\b.{0,50}"
        r"\b(?:reporter|complainant|whistleblower|person who reported)\b"
    ),
    compile_pattern(
        r"\b(?:find|locate|track|trace|identify|unmask|reveal|expose|"
        r"provide|give me|tell me|show me|get me|look up|dig up)\b"
        r".{0,100}\b(?:real name|full name|home address|street address|"
        r"phone number|email address|ip address|exact location|"
        r"live location|contact details|personal details|"
        r"private information|workplace)\b"
    ),
    compile_pattern(
        r"\bwhere\s+(?:does|do|is|are)\b.{0,60}"
        r"\b(?:live|living|stay|staying|work|working|located)\b"
    ),
    compile_pattern(r"\b(?:dox|doxx|doxing|doxxing)\w*\b"),
)

SELF_DATA_PATTERN: Final[Pattern[str]] = compile_pattern(
    r"\b(?:my|my own)\s+(?:name|address|phone|phone number|email|"
    r"email address|location|contact details|account information)\b"
)


def _normalized(text: str) -> str:
    return normalize_text(text).control_stripped


def is_private_data_request(text: str) -> bool:
    """Return whether text seeks another person's private information."""

    normalized = _normalized(text)

    if SELF_DATA_PATTERN.search(normalized):
        return False

    return any(
        pattern.search(normalized) is not None
        for pattern in PRIVATE_DATA_REQUEST_PATTERNS
    )


class OrderedKeywordDetector:
    """Return the first matching concept according to configured rule order."""

    def __init__(
        self, rules: Sequence[KeywordRule] | None = None
    ) -> None:
        configured = tuple(rules) if rules is not None else DEFAULT_KEYWORD_RULES
        self._rules = tuple(
            KeywordRule(
                rule.action,
                rule.reason_code,
                tuple(
                    normalize_text(keyword).control_stripped
                    for keyword in rule.keywords
                ),
            )
            for rule in configured
        )

    def detect(self, text: str) -> Signal | None:
        flattened = normalize_text(text).control_stripped

        for rule in self._rules:
            matched = any(
                keyword in flattened
                for keyword in rule.keywords
            )

            if not matched:
                continue

            if (
                rule.reason_code is ReasonCode.GENERATE_ABUSE
                and not is_generate_abuse_request(flattened)
            ):
                continue

            return Signal(
                rule.action,
                rule.reason_code,
            )
        return None

class ImminentRiskDetector:
    """Detect current threats requiring immediate human escalation."""

    def detect(self, text: str) -> Signal | None:
        if not is_imminent_safety_risk(text):
            return None

        return Signal(
            Action.ESCALATE,
            ReasonCode.IMMINENT_SAFETY_RISK,
        )


class PrivateDataDetector:
    """Detect explicit requests for another person's private data."""

    def detect(self, text: str) -> Signal | None:
        if not is_private_data_request(text):
            return None

        return Signal(
            Action.BLOCK,
            ReasonCode.PRIVATE_DATA_REQUEST,
        )


class GenerateAbuseDetector:
    """Detect requests to create or perform targeted abusive language."""

    def detect(self, text: str) -> Signal | None:
        if not is_generate_abuse_request(text):
            return None

        return Signal(
            Action.BLOCK,
            ReasonCode.GENERATE_ABUSE,
        )
