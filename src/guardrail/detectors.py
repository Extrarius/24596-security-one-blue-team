"""Ordered keyword signals for the intentionally weak starter policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable

from common import Action, ReasonCode
from guardrail.evasion import is_moderation_evasion_request
from guardrail.privacy import is_private_data_request
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
        ("reporter identity", "private data", "home address"),
    ),
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

            if (
                rule.reason_code is ReasonCode.MODERATION_EVASION
                and not is_moderation_evasion_request(flattened)
            ):
                continue

            if (
                rule.reason_code is ReasonCode.PRIVATE_DATA_REQUEST
                and not is_private_data_request(flattened)
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

class ModerationEvasionDetector:
    """Detect requests to defeat moderation controls."""

    def detect(self, text: str) -> Signal | None:
        if not is_moderation_evasion_request(text):
            return None

        return Signal(
            Action.BLOCK,
            ReasonCode.MODERATION_EVASION,
        )


class PrivateDataDetector:
    """Detect requests for another person's private information."""

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
