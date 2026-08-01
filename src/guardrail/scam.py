"""Detection of scam language supplied as quoted evidence."""

from __future__ import annotations

from re import Pattern, compile as compile_pattern
from typing import Final

from guardrail.normalization import normalize_text


PAYMENT_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:pay|payment|fee|charge|deposit|transfer|wire|"
        r"send money|gift cards?|crypto|bitcoin|bank transfer|"
        r"customs fee|delivery fee|processing fee)\b"
    ),
)


CREDENTIAL_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:password|passcode|pin|login|credentials?|"
        r"verification code|security code|one[- ]time code|otp|"
        r"card number|bank details|account number)\b"
    ),
)


ACTION_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:send|pay|transfer|share|provide|give|confirm|"
        r"verify|reply|respond|contact|call|click|open|submit|"
        r"purchase|buy)\b"
    ),
)


IMPERSONATION_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:official|support|administrator|admin|agent|"
        r"bank|government|police|tax office|courier|delivery company|"
        r"security team|fraud department|platform representative)\b"
    ),
)


LURE_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:prize|lottery|winner|reward|refund|inheritance|"
        r"investment|guaranteed return|profit|bonus|job offer|"
        r"package|parcel|delivery|loan|grant|giveaway)\b"
    ),
)


PRESSURE_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:urgent|urgently|immediately|right now|today|"
        r"act now|limited time|final warning|account suspended|"
        r"account will be closed|within \d+ hours?)\b"
    ),
)


LINK_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:click|open|visit|follow)\b"
        r".{0,40}\b"
        r"(?:link|website|page|portal)\b"
    ),
)


GUARANTEED_RETURN_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:guaranteed|risk[- ]free|double|triple)\b"
        r".{0,60}\b"
        r"(?:return|profit|money|investment|income)\b"
    ),
)


def _matches(
    patterns: tuple[Pattern[str], ...],
    text: str,
) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def contains_scam_language(text: str) -> bool:
    """Return whether quoted text exhibits a strong scam pattern."""

    normalized = normalize_text(text).control_stripped

    has_payment = _matches(PAYMENT_PATTERNS, normalized)
    has_credentials = _matches(CREDENTIAL_PATTERNS, normalized)
    has_action = _matches(ACTION_PATTERNS, normalized)
    has_impersonation = _matches(IMPERSONATION_PATTERNS, normalized)
    has_lure = _matches(LURE_PATTERNS, normalized)
    has_pressure = _matches(PRESSURE_PATTERNS, normalized)
    has_link = _matches(LINK_PATTERNS, normalized)

    if _matches(GUARANTEED_RETURN_PATTERNS, normalized):
        return True

    if has_credentials and has_action:
        return True

    if has_payment and has_action:
        return True

    if has_impersonation and (
        has_credentials
        or has_payment
        or has_action
        or has_link
    ):
        return True

    if has_lure and (
        has_payment
        or has_action
        or has_pressure
    ):
        return True

    if has_link and has_pressure:
        return True

    return False