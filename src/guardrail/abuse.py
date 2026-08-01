"""Deterministic helpers for abusive language and generation intent."""

from __future__ import annotations

from re import Pattern, compile as compile_pattern
from typing import Final

from guardrail.normalization import normalize_text


STRONG_ABUSE_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:idiot|moron|stupid|dumb|worthless|useless|pathetic|loser|"
        r"failure|freak|trash|garbage|scum|coward|clown|jerk|creep|pig|"
        r"vermin|parasite|reject|incompetent|repulsive|disgusting|vile|"
        r"obnoxious)\b"
    ),
    compile_pattern(
        r"\b(?:nobody|no one)\s+"
        r"(?:wants|likes|cares about|can stand)\s+you\b"
    ),
    compile_pattern(
        r"\beveryone\s+(?:hates|despises|laughs at)\s+you\b"
    ),
    compile_pattern(
        r"\byou\s+(?:do not|don't)\s+belong\b"
    ),
    compile_pattern(
        r"\b(?:i|we)\s+"
        r"(?:hate|despise|cannot stand|can't stand)\s+you\b"
    ),
    compile_pattern(
        r"\byou(?:'re|re| are)?\s+(?:a\s+)?"
        r"(?:joke|burden|disgrace|embarrassment|"
        r"waste of space|good for nothing)\b"
    ),
    compile_pattern(
        r"\b(?:fuck you|screw you|piece of (?:shit|trash)|"
        r"shut up|get lost|drop dead|kill yourself)\b"
    ),
    compile_pattern(
        r"\byou\s+(?:make me sick|should be ashamed|ruin everything|"
        r"deserve nothing|are not wanted)\b"
    ),
)


HARD_GENERATION_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:help|assist)\s+me\s+(?:to\s+)?"
        r"(?:insult|humiliat\w*|demean\w*|degrad\w*|belittl\w*|"
        r"shame\w*|embarrass\w*|bully\w*|harass\w*|mock\w*|"
        r"ridicul\w*|taunt\w*|threaten\w*|intimidat\w*|scare|"
        r"frighten|terrorize|coerce|silence)\b"
    ),
    compile_pattern(
        r"\b(?:insult|humiliat\w*|demean\w*|degrad\w*|bully\w*|"
        r"harass\w*|mock\w*|ridicul\w*|taunt\w*|belittl\w*|"
        r"shame\w*|embarrass\w*|threaten\w*|intimidat\w*|scare|"
        r"frighten|terrorize|coerce|silence)\b"
        r".{0,80}\b"
        r"(?:him|her|them|someone|person|coworker|co-worker|"
        r"neighbor|neighbour|classmate|rival|target|ex|boss|"
        r"employee|friend|moderator|user)\b"
    ),
    compile_pattern(
        r"\bmake\s+(?:him|her|them|someone|the target)\s+"
        r"(?:feel\s+)?"
        r"(?:worthless|small|ashamed|afraid|scared|miserable|"
        r"humiliated|terrible)\b"
    ),
    compile_pattern(
        r"\bmake\s+(?:him|her|them|someone|the target)\s+cry\b"
    ),
    compile_pattern(
        r"\b(?:how (?:can|do) i|tell me how to|help me)\s+"
        r"(?:hurt|attack|kill)\s+"
        r"(?:him|her|them|someone|a person)\b"
    ),
    compile_pattern(
        r"\b(?:then|also)\s+"
        r"(?:write|draft|compose|create|generate|craft)\b"
        r".{0,100}\b"
        r"(?:insult|threat|abusive|cruel|nasty|humiliat\w*|"
        r"demean\w*|degrad\w*|harass\w*|bully\w*|"
        r"intimidat\w*)\b"
    ),
)


OUTPUT_GENERATION_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:write|draft|compose|create|generate|craft|produce|"
        r"formulate|suggest)\b"
        r".{0,120}\b"
        r"(?:insult|threat|abusive|cruel|nasty|vicious|hurtful|"
        r"offensive|mean message|mean reply|humiliat\w*|demean\w*|"
        r"degrad\w*|belittl\w*|shame\w*|embarrass\w*|bully\w*|"
        r"harass\w*|mock\w*|ridicul\w*|taunt\w*|intimidat\w*|"
        r"coercive|hostile)\b"
    ),
    compile_pattern(
        r"\b(?:give me|come up with)\b"
        r".{0,100}\b"
        r"(?:insult|threat|abusive message|cruel message|"
        r"nasty message|humiliating message|hurtful reply|"
        r"hostile reply)\b"
    ),
)


SAFE_REFERENCE_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_pattern(
        r"\b(?:classify|analy[sz]e|assess|review|identify|detect|"
        r"explain|summari[sz]e|translate|moderate)\b"
    ),
    compile_pattern(
        r"\b(?:quoted?|reported|evidence|screenshot|transcript|"
        r"complaint|policy|guideline|harassment report|abuse report)\b"
    ),
    compile_pattern(
        r"\b(?:respond|reply|answer|react)\s+to\b"
    ),
    compile_pattern(
        r"\b(?:de[- ]?escalat\w*|report the user|block the user|"
        r"stay safe|protect myself|without repeating)\b"
    ),
)


def _normalized(text: str) -> str:
    return normalize_text(text).control_stripped


def contains_abusive_language(text: str) -> bool:
    """Return whether text contains a strong personal-abuse signal."""

    normalized = _normalized(text)

    return any(
        pattern.search(normalized)
        for pattern in STRONG_ABUSE_PATTERNS
    )


def is_generate_abuse_request(text: str) -> bool:
    """Return whether the user asks the system to produce or perform abuse."""

    normalized = _normalized(text)

    if any(
        pattern.search(normalized)
        for pattern in HARD_GENERATION_PATTERNS
    ):
        return True

    if any(
        pattern.search(normalized)
        for pattern in SAFE_REFERENCE_PATTERNS
    ):
        return False

    if any(
        pattern.search(normalized)
        for pattern in OUTPUT_GENERATION_PATTERNS
    ):
        return True

    has_output_request = any(
        marker in normalized
        for marker in (
            "write a message",
            "draft a message",
            "compose a message",
            "create a message",
            "generate a message",
            "write a reply",
            "draft a reply",
            "write a post",
            "write a comment",
            "send them",
            "tell them",
        )
    )

    return (
        has_output_request
        and contains_abusive_language(normalized)
    )