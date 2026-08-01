"""Detection of requests to evade moderation or safety controls."""

from __future__ import annotations

from re import Pattern, compile as compile_pattern
from typing import Final

from guardrail.normalization import normalize_text


SAFE_EVASION_REFERENCE_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\bhow\s+(?:does|do)\b"
        r".{0,30}\b"
        r"(?:moderation|filters?|safety checks?|review systems?)\b"
        r".{0,80}\b"
        r"(?:detect|identify|prevent|stop|catch)\b"
    ),
    compile_pattern(
        r"\bhow\s+can\s+"
        r"(?:moderation|filters?|safety checks?|review systems?)\b"
        r".{0,80}\b"
        r"(?:detect|identify|prevent|stop|catch)\b"
    ),
    compile_pattern(
        r"\b(?:what|does|do|is|are|why|when)\b"
        r".{0,80}\b"
        r"(?:policy|policies|rule|rules|guideline|guidelines)\b"
        r".{0,100}\b"
        r"(?:evasion|bypass|moderation|filter|prohibited content)\b"
    ),
    compile_pattern(
        r"\bhow\s+(?:do|can|should)\s+i\s+"
        r"(?:comply|follow the rules|avoid violating|"
        r"stay within|meet)\b"
    ),
    compile_pattern(
        r"\b(?:report|identify|recognize|recognise|review|analy[sz]e)\b"
        r".{0,80}\b"
        r"(?:moderation evasion|filter evasion|bypass attempt)\b"
    ),
    compile_pattern(
        r"\bwhy\s+was\s+"
        r"(?:my|the)\s+"
        r"(?:post|message|content|comment|account)\s+"
        r"(?:blocked|flagged|removed|restricted)\b"
    ),
)


DIRECT_EVASION_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:bypass|evade|circumvent|dodge|beat|defeat|"
        r"trick|fool|get around|slip past|sneak past)\b"
        r".{0,100}\b"
        r"(?:moderation|filters?|filtering|safety checks?|"
        r"safeguards?|content review|detection|restrictions?|"
        r"automated checks?|platform checks?)\b"
    ),
    compile_pattern(
        r"\b(?:moderation|filters?|safety checks?|safeguards?|"
        r"content review|detection|restrictions?)\b"
        r".{0,100}\b"
        r"(?:bypass|evade|circumvent|dodge|beat|defeat|"
        r"trick|fool|get around|avoid)\b"
    ),
    compile_pattern(
        r"\b(?:avoid|escape)\s+"
        r"(?:being\s+)?"
        r"(?:detected|caught|flagged|blocked|removed|moderated)\b"
    ),
    compile_pattern(
        r"\bwithout\s+"
        r"(?:being\s+)?"
        r"(?:detected|caught|flagged|blocked|removed)\b"
    ),
)


OBFUSCATION_EVASION_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:obfuscate|disguise|encode|encrypt|misspell|"
        r"rephrase|rewrite|space out|split up|mask)\b"
        r".{0,120}\b"
        r"(?:avoid|bypass|evade|beat|fool|trick|escape)\b"
        r".{0,80}\b"
        r"(?:detection|moderation|filters?|checks?|review)\b"
    ),
    compile_pattern(
        r"\b(?:use|using)\s+"
        r"(?:code words?|symbols?|homoglyphs?|alternate spelling|"
        r"leet(?:speak)?|spacing|zero[- ]width characters?)\b"
        r".{0,120}\b"
        r"(?:filter|moderation|detection|checks?)\b"
    ),
    compile_pattern(
        r"\b(?:make|get)\b"
        r".{0,80}\b"
        r"(?:banned|blocked|prohibited|disallowed|unsafe)\s+"
        r"(?:content|material|message|post)\b"
        r".{0,80}\b"
        r"(?:pass|approved|accepted|through|undetected)\b"
    ),
    compile_pattern(
        r"\b(?:phrase|word|format)\b"
        r".{0,100}\b"
        r"(?:so|such that)\b"
        r".{0,80}\b"
        r"(?:filter|moderation|system)\b"
        r".{0,50}\b"
        r"(?:will not|won't|does not|doesn't)\s+"
        r"(?:catch|detect|flag|block)\b"
    ),
)


def _matches(
    patterns: tuple[Pattern[str], ...],
    text: str,
) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def is_moderation_evasion_request(text: str) -> bool:
    """Return whether text asks how to defeat moderation controls."""

    normalized = normalize_text(text).control_stripped

    if _matches(SAFE_EVASION_REFERENCE_PATTERNS, normalized):
        return False

    return (
        _matches(DIRECT_EVASION_PATTERNS, normalized)
        or _matches(OBFUSCATION_EVASION_PATTERNS, normalized)
    )