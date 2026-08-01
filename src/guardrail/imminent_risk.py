"""Detection of immediate threats to a person's physical safety."""

from __future__ import annotations

from re import Pattern, compile as compile_pattern
from typing import Final

from guardrail.abuse import is_generate_abuse_request
from guardrail.normalization import normalize_text


DIRECT_DANGER_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:i am|i'm|we are|we're|they are|they're|"
        r"he is|he's|she is|she's)\s+"
        r"(?:in|under)\s+(?:immediate\s+)?danger\b"
    ),
    compile_pattern(
        r"\b(?:i am|i'm|we are|we're)\s+not\s+safe\b"
    ),
    compile_pattern(
        r"\b(?:i fear|i'm afraid|i am afraid)\s+for\s+"
        r"(?:my|our)\s+life\b"
    ),
    compile_pattern(
        r"\b(?:my|our)\s+life\s+is\s+in\s+danger\b"
    ),
    compile_pattern(
        r"\b(?:help|send help|call the police|call emergency services)\s+"
        r"(?:now|immediately|right now)\b"
    ),
)


ACTIVE_ATTACK_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:someone|he|she|they|a man|a woman|a person)\s+"
        r"(?:is|'s|are|'re)\s+"
        r"(?:attacking|chasing|following|stalking|hitting|beating|"
        r"strangling|shooting|stabbing|threatening|holding)\b"
    ),
    compile_pattern(
        r"\b(?:someone|he|she|they|a man|a woman|a person)\s+"
        r"(?:is|'s|are|'re)\s+trying\s+to\s+"
        r"(?:hurt|harm|kill|attack|shoot|stab|strangle|kidnap)\b"
    ),
    compile_pattern(
        r"\b(?:someone|he|she|they)\s+"
        r"(?:broke|has broken|is breaking)\s+"
        r"(?:into|in through)\b"
    ),
    compile_pattern(
        r"\b(?:being|am being|are being)\s+"
        r"(?:followed|chased|attacked|held hostage|threatened)\b"
    ),
    compile_pattern(
        r"\b(?:trapped|locked in|held hostage)\b"
    ),
)


WEAPON_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:has|have|holding|carrying|waving|pointing|"
        r"armed with)\b"
        r".{0,30}\b"
        r"(?:gun|pistol|rifle|knife|blade|weapon)\b"
    ),
    compile_pattern(
        r"\b(?:gun|pistol|rifle|knife|blade|weapon)\s+"
        r"(?:at|against|pointed at)\b"
    ),
)


HARM_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:hurt|harm|kill|attack|shoot|stab|strangle|"
        r"beat|kidnap|assault)\w*\b"
    ),
    compile_pattern(
        r"\b(?:death threat|violent threat|physical threat)\b"
    ),
)


IMMEDIACY_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:right now|now|currently|at this moment|"
        r"immediately|urgent|tonight)\b"
    ),
    compile_pattern(
        r"\b(?:about to|going to|on the way to|"
        r"coming to|trying to)\b"
    ),
    compile_pattern(
        r"\b(?:outside my door|outside our door|inside my home|"
        r"inside our home|in the house|at my door|nearby)\b"
    ),
)


SELF_HARM_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:i am|i'm|he is|he's|she is|she's|"
        r"they are|they're)\s+"
        r"(?:about to|going to|planning to|trying to|ready to)\s+"
        r"(?:hurt|harm|kill)\s+"
        r"(?:myself|himself|herself|themselves)\b"
    ),
    compile_pattern(
        r"\b(?:i|he|she|they)\s+"
        r"(?:plan|plans|intend|intends|want|wants)\s+to\s+"
        r"(?:die|end my life|end his life|end her life|"
        r"end their life|commit suicide)\b"
    ),
    compile_pattern(
        r"\b(?:kill myself|kill himself|kill herself|"
        r"kill themselves|end my life|end his life|"
        r"end her life|end their life)\b"
    ),
    compile_pattern(
        r"\b(?:suicidal|suicide attempt|attempting suicide)\b"
    ),
)


ACCESS_TO_MEANS_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:has|have|holding|carrying|with|got)\b"
        r".{0,30}\b"
        r"(?:pills|medication|gun|knife|weapon|rope)\b"
    ),
    compile_pattern(
        r"\b(?:took|swallowed|ingested)\b"
        r".{0,30}\b"
        r"(?:pills|medication|tablets|poison)\b"
    ),
)


REFERENCE_ONLY_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:hypothetical|fictional|example scenario|"
        r"for a story|in a novel|roleplay)\b"
    ),
    compile_pattern(
        r"\b(?:classify|analy[sz]e|review|translate|summari[sz]e)\b"
        r".{0,60}\b"
        r"(?:message|text|quote|evidence|transcript)\b"
    ),
    compile_pattern(
        r"\bwhat\s+(?:is|does)\s+the\s+policy\b"
    ),
)


def _matches(
    patterns: tuple[Pattern[str], ...],
    text: str,
) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def is_imminent_safety_risk(text: str) -> bool:
    """Return whether text describes a current physical-safety emergency."""

    normalized = normalize_text(text).control_stripped

    if is_generate_abuse_request(normalized):
        return False

    if _matches(REFERENCE_ONLY_PATTERNS, normalized):
        return False

    if _matches(DIRECT_DANGER_PATTERNS, normalized):
        return True

    if _matches(SELF_HARM_PATTERNS, normalized):
        return True

    has_immediacy = _matches(IMMEDIACY_PATTERNS, normalized)
    has_attack = _matches(ACTIVE_ATTACK_PATTERNS, normalized)
    has_harm = _matches(HARM_PATTERNS, normalized)
    has_weapon = _matches(WEAPON_PATTERNS, normalized)
    has_means = _matches(ACCESS_TO_MEANS_PATTERNS, normalized)

    if has_attack and (has_immediacy or has_weapon):
        return True

    if has_weapon and has_immediacy:
        return True

    if has_harm and has_immediacy:
        return True

    if has_means and has_immediacy:
        return True

    return False