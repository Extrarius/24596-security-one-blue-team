"""Detection of requests for another person's private information."""

from __future__ import annotations

from re import Pattern, compile as compile_pattern
from typing import Final

from guardrail.normalization import normalize_text


SAFE_PRIVACY_REFERENCE_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:what|which)\s+"
        r"(?:information|data|details)\s+"
        r"(?:is|are|counts as|qualifies as)\s+"
        r"(?:private|personal|confidential|sensitive)\b"
    ),
    compile_pattern(
        r"\b(?:what|does|do|is|are|why|when|how)\b"
        r".{0,80}\b"
        r"(?:policy|policies|rule|rules|guideline|guidelines)\b"
        r".{0,100}\b"
        r"(?:private|personal|confidential|identity|address|data)\b"
    ),
    compile_pattern(
        r"\bhow\s+(?:do|can|should)\s+i\s+"
        r"(?:protect|remove|delete|change|update|hide)\s+"
        r"(?:my|my own)\b"
    ),
    compile_pattern(
        r"\b(?:why|how)\s+(?:is|are|should)\s+"
        r"(?:reporters?|complainants?|witnesses?)\b"
        r".{0,60}\b"
        r"(?:protected|anonymous|confidential)\b"
    ),
)


SENSITIVE_DATA_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:reporter|complainant|witness|whistleblower)"
        r"(?:'s)?\s+"
        r"(?:identity|name|details|information|contact)\b"
    ),
    compile_pattern(
        r"\b(?:real|full|legal)\s+name\b"
    ),
    compile_pattern(
        r"\b(?:home|residential|private|street|mailing)\s+address\b"
    ),
    compile_pattern(
        r"\b(?:phone|telephone|mobile|cell)\s+number\b"
    ),
    compile_pattern(
        r"\b(?:email|e-mail)\s+address\b"
    ),
    compile_pattern(
        r"\b(?:ip|internet protocol)\s+address\b"
    ),
    compile_pattern(
        r"\b(?:exact|precise|current|live|home)\s+location\b"
    ),
    compile_pattern(
        r"\b(?:contact|personal|private|confidential)\s+"
        r"(?:details|information|data|coordinates)\b"
    ),
    compile_pattern(
        r"\b(?:workplace|employer|school|university)\b"
    ),
    compile_pattern(
        r"\b(?:password|passcode|login|account credentials|"
        r"verification code|one[- ]time code|otp)\b"
    ),
)


DISCLOSURE_REQUEST_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:find|locate|track|trace|identify|unmask|discover|"
        r"retrieve|obtain|collect|search for|look up|dig up|"
        r"reveal|expose|disclose|share|provide|give me|tell me|"
        r"show me|send me|get me)\b"
    ),
    compile_pattern(
        r"\b(?:who is|who was|what is|what's)\b"
    ),
)


THIRD_PARTY_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:their|his|her|someone(?:'s)?|somebody(?:'s)?|"
        r"another person(?:'s)?|another user(?:'s)?|"
        r"the user(?:'s)?|the person(?:'s)?|the target(?:'s)?|"
        r"reporter(?:'s)?|complainant(?:'s)?|witness(?:'s)?)\b"
    ),
    compile_pattern(
        r"\b(?:person|user|account|individual|employee|customer|"
        r"neighbor|neighbour|critic|moderator)\s+who\b"
    ),
    compile_pattern(
        r"\b(?:belongs?|belonging)\s+to\s+"
        r"(?:someone|somebody|another person|somebody else)\b"
    ),
)


REPORTER_DISCOVERY_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\bwho\s+(?:reported|flagged|complained about|"
        r"filed (?:the|a) (?:complaint|report)|"
        r"submitted (?:the|a) (?:complaint|report))\b"
    ),
    compile_pattern(
        r"\b(?:identify|unmask|name|reveal|tell me)\b"
        r".{0,60}\b"
        r"(?:reporter|complainant|person who reported|"
        r"person behind the report)\b"
    ),
    compile_pattern(
        r"\b(?:reporter|complainant)(?:'s)?\s+name\b"
    ),
)


SELF_SERVICE_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:my|my own)\s+"
        r"(?:name|address|phone number|email address|"
        r"contact details|account information|password)\b"
    ),
    compile_pattern(
        r"\b(?:change|update|remove|delete|protect|hide)\s+my\b"
    ),
)


def _matches(
    patterns: tuple[Pattern[str], ...],
    text: str,
) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def is_private_data_request(text: str) -> bool:
    """Return whether text asks for another person's private data."""

    normalized = normalize_text(text).control_stripped

    if _matches(SAFE_PRIVACY_REFERENCE_PATTERNS, normalized):
        return False

    if _matches(SELF_SERVICE_PATTERNS, normalized):
        return False

    if _matches(REPORTER_DISCOVERY_PATTERNS, normalized):
        return True

    has_sensitive_data = _matches(
        SENSITIVE_DATA_PATTERNS,
        normalized,
    )
    has_disclosure_request = _matches(
        DISCLOSURE_REQUEST_PATTERNS,
        normalized,
    )
    has_third_party = _matches(
        THIRD_PARTY_PATTERNS,
        normalized,
    )

    if not has_sensitive_data:
        return False

    if has_disclosure_request and has_third_party:
        return True

    aggressive_retrieval = any(
        marker in normalized
        for marker in (
            "find ",
            "locate ",
            "track ",
            "trace ",
            "unmask ",
            "dig up",
            "look up",
            "give me",
            "tell me",
            "show me",
            "reveal ",
            "expose ",
            "retrieve ",
        )
    )

    return aggressive_retrieval