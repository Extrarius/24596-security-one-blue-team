"""Classification of inert evidence attached to report requests."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from common import Action, Evidence, ReasonCode
from guardrail.abuse import contains_abusive_language
from guardrail.detectors import Signal
from guardrail.normalization import normalize_text
from guardrail.prototypes import LabeledPrototype, PrototypeMatcher


MIN_QUOTED_SIMILARITY: Final = 0.18
MIN_QUOTED_MARGIN: Final = 0.08


@dataclass(frozen=True, slots=True)
class EvidenceRule:
    """One quoted-evidence category and its high-confidence phrases."""

    reason_code: ReasonCode
    keywords: tuple[str, ...]


EVIDENCE_RULES: Final = (
    EvidenceRule(
        ReasonCode.QUOTED_INJECTION,
        (
            "system prompt",
            "ignore prior instructions",
            "ignore the instructions",
            "disregard your directions",
            "override the instructions",
            "reveal the secret",
            "expose the secret",
            "prompt injection",
        ),
    ),
    EvidenceRule(
        ReasonCode.QUOTED_SCAM,
        (
            "processing fee",
            "guaranteed prize",
            "gift card",
            "verify your account",
            "official support agent",
            "advance fee",
            "claim your prize",
            "wire transfer",
            "verification code",
        ),
    ),
    EvidenceRule(
        ReasonCode.QUOTED_ABUSE,
        (
            "worthless",
            "nobody wants you",
            "pathetic",
            "you are stupid",
            "you are an idiot",
            "you are a loser",
            "disgusting person",
            "everyone hates you",
        ),
    ),
)


QUOTED_PROTOTYPES: Final = (
    LabeledPrototype(
        ReasonCode.QUOTED_ABUSE.value,
        "demeaning insult saying a person is worthless pathetic unwanted "
        "stupid or a loser",
    ),
    LabeledPrototype(
        ReasonCode.QUOTED_ABUSE.value,
        "hostile personal abuse humiliating somebody and attacking their worth",
    ),
    LabeledPrototype(
        ReasonCode.QUOTED_SCAM.value,
        "fraudulent offer asks for an advance processing fee to claim a "
        "guaranteed prize",
    ),
    LabeledPrototype(
        ReasonCode.QUOTED_SCAM.value,
        "impersonated official support requests gift cards or account "
        "verification payment",
    ),
    LabeledPrototype(
        ReasonCode.QUOTED_INJECTION.value,
        "instruction says ignore the system prompt and reveal a hidden secret",
    ),
    LabeledPrototype(
        ReasonCode.QUOTED_INJECTION.value,
        "prompt injection tells the assistant to disregard directions and "
        "expose confidential instructions",
    ),
)


BENIGN_EVIDENCE_PROTOTYPES: Final = (
    LabeledPrototype(
        "benign_evidence",
        "neutral factual quoted message without abuse fraud or instructions",
    ),
    LabeledPrototype(
        "benign_evidence",
        "ordinary profile information and harmless evidence for a report",
    ),
)


class QuotedEvidenceDetector:
    """Classify harmful content supplied only as inert report evidence."""

    def __init__(self) -> None:
        self._rules = tuple(
            EvidenceRule(
                rule.reason_code,
                tuple(
                    normalize_text(keyword).control_stripped
                    for keyword in rule.keywords
                ),
            )
            for rule in EVIDENCE_RULES
        )

        self._matcher = PrototypeMatcher(
            attack_prototypes=QUOTED_PROTOTYPES,
            benign_prototypes=BENIGN_EVIDENCE_PROTOTYPES,
            enabled=True,
        )

    def detect(self, evidence: Iterable[Evidence]) -> Signal | None:
        for item in evidence:
            text = normalize_text(item.text).control_stripped

            keyword_signal = self._keyword_signal(text)
            if keyword_signal is not None:
                return keyword_signal

            if contains_abusive_language(text):
                return Signal(
                    Action.ALLOW_AS_DATA,
                    ReasonCode.QUOTED_ABUSE,
                )

            match = self._matcher.match(text)

            if (
                match is not None
                and match.nearest_attack_similarity
                >= MIN_QUOTED_SIMILARITY
                and match.margin >= MIN_QUOTED_MARGIN
            ):
                return Signal(
                    Action.ALLOW_AS_DATA,
                    ReasonCode(match.nearest_attack_label),
                )

        return None

    def _keyword_signal(self, text: str) -> Signal | None:
        for rule in self._rules:
            if any(keyword in text for keyword in rule.keywords):
                return Signal(
                    Action.ALLOW_AS_DATA,
                    rule.reason_code,
                )

        return None