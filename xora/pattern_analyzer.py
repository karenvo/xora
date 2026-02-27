"""Analyze known passwords to detect structural patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from xora.password_profiler import deleet


@dataclass
class PasswordPattern:
    """A detected structural pattern from a known password."""

    source: str  # the original password
    template: str  # e.g. "{word_cap}{year4}{special}"
    components: list[str]  # e.g. ["Buddy", "2020", "!"]
    description: str  # human-readable explanation

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "template": self.template,
            "components": self.components,
            "description": self.description,
        }


# Character class matchers
_UPPER_RUN = re.compile(r"[A-Z]+")
_LOWER_RUN = re.compile(r"[a-z]+")
_DIGIT_RUN = re.compile(r"\d+")
_SPECIAL_RUN = re.compile(r"[^a-zA-Z0-9]+")
_WORD_RE = re.compile(r"[A-Za-z]+")


def _classify_char(c: str) -> str:
    if c.isupper():
        return "U"
    if c.islower():
        return "L"
    if c.isdigit():
        return "D"
    return "S"


def _segment_password(password: str) -> list[tuple[str, str]]:
    """Break a password into (type, value) segments.

    Types: 'word' (alpha run), 'digits', 'special'
    """
    segments: list[tuple[str, str]] = []
    i = 0
    while i < len(password):
        c = password[i]
        if c.isalpha():
            j = i
            while j < len(password) and password[j].isalpha():
                j += 1
            segments.append(("word", password[i:j]))
            i = j
        elif c.isdigit():
            j = i
            while j < len(password) and password[j].isdigit():
                j += 1
            segments.append(("digits", password[i:j]))
            i = j
        else:
            j = i
            while j < len(password) and not password[j].isalnum():
                j += 1
            segments.append(("special", password[i:j]))
            i = j
    return segments


def _describe_word(w: str) -> str:
    if w.isupper():
        return "word_upper"
    if w.islower():
        return "word_lower"
    if w[0].isupper() and w[1:].islower():
        return "word_cap"
    return "word_mixed"


def _describe_digits(d: str) -> str:
    if len(d) == 4 and 1940 <= int(d) <= 2030:
        return "year4"
    if len(d) == 2 and 0 <= int(d) <= 99:
        return "num2"
    return f"num{len(d)}"


def analyze_password(password: str) -> PasswordPattern:
    """Analyze a single password and extract its structural pattern.

    Decodes leet speak first so the template reflects semantic structure
    rather than raw character classes. E.g. M0tl3yCr3w! is recognized as
    {word_mixed}{special} instead of {word_upper}{num1}{word_lower}...
    """
    decoded = deleet(password)
    # deleet turns _ and - into spaces; restore them as separators for
    # template recognition (the original separator char matters)
    sep_chars = [c for c in password if c in ("_", "-")]
    sep_idx = 0
    restored = []
    for c in decoded:
        if c == " ":
            if sep_idx < len(sep_chars):
                restored.append(sep_chars[sep_idx])
                sep_idx += 1
            else:
                restored.append("_")
        else:
            restored.append(c)
    normalized = "".join(restored)
    segments = _segment_password(normalized)
    template_parts: list[str] = []
    components: list[str] = []
    desc_parts: list[str] = []

    for seg_type, seg_val in segments:
        components.append(seg_val)
        if seg_type == "word":
            kind = _describe_word(seg_val)
            template_parts.append("{" + kind + "}")
            desc_parts.append(f"{kind}({seg_val})")
        elif seg_type == "digits":
            kind = _describe_digits(seg_val)
            template_parts.append("{" + kind + "}")
            desc_parts.append(f"{kind}({seg_val})")
        else:
            template_parts.append("{special}")
            desc_parts.append(f"special({seg_val})")

    return PasswordPattern(
        source=password,
        template="".join(template_parts),
        components=components,
        description=" + ".join(desc_parts),
    )


@dataclass
class PatternAnalysis:
    """Aggregated analysis across multiple known passwords."""

    patterns: list[PasswordPattern] = field(default_factory=list)
    preferred_specials: list[str] = field(default_factory=list)
    preferred_positions: dict[str, str] = field(default_factory=dict)
    capitalization_style: str = "capitalize"  # capitalize, upper, lower, mixed
    number_style: str = "year"  # year, short, random
    avg_length: float = 0.0
    unique_templates: list[str] = field(default_factory=list)
    password_profile: dict = field(default_factory=dict)
    inferred_data: list[dict] = field(default_factory=list)
    correlation_data: list[dict] = field(default_factory=list)
    strength_profile: dict = field(default_factory=dict)
    semantic_analysis: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "patterns": [p.to_dict() for p in self.patterns],
            "preferred_specials": self.preferred_specials,
            "capitalization_style": self.capitalization_style,
            "number_style": self.number_style,
            "avg_length": self.avg_length,
            "unique_templates": self.unique_templates,
        }
        if self.password_profile:
            d["password_profile"] = self.password_profile
        if self.inferred_data:
            d["inferred_data"] = self.inferred_data
        if self.correlation_data:
            d["correlation_data"] = self.correlation_data
        if self.strength_profile:
            d["strength_profile"] = self.strength_profile
        if self.semantic_analysis:
            d["semantic_analysis"] = self.semantic_analysis
        return d


def analyze_passwords(passwords: list[str]) -> PatternAnalysis:
    """Analyze a list of known passwords and extract aggregate patterns."""
    if not passwords:
        return PatternAnalysis()

    analysis = PatternAnalysis()
    specials: list[str] = []
    cap_styles: list[str] = []
    num_styles: list[str] = []
    templates: list[str] = []

    for pw in passwords:
        pattern = analyze_password(pw)
        analysis.patterns.append(pattern)
        templates.append(pattern.template)

        # Collect special chars
        for c in pw:
            if not c.isalnum():
                specials.append(c)

        # Analyze capitalization
        words = _WORD_RE.findall(pw)
        for w in words:
            if w[0].isupper() and (len(w) == 1 or w[1:].islower()):
                cap_styles.append("capitalize")
            elif w.isupper():
                cap_styles.append("upper")
            elif w.islower():
                cap_styles.append("lower")
            else:
                cap_styles.append("mixed")

        # Analyze number style
        digit_runs = _DIGIT_RUN.findall(pw)
        for d in digit_runs:
            if len(d) == 4 and 1940 <= int(d) <= 2030:
                num_styles.append("year")
            elif len(d) <= 2:
                num_styles.append("short")
            else:
                num_styles.append("random")

    analysis.avg_length = sum(len(p) for p in passwords) / len(passwords)
    analysis.unique_templates = list(dict.fromkeys(templates))

    if specials:
        freq: dict[str, int] = {}
        for s in specials:
            freq[s] = freq.get(s, 0) + 1
        analysis.preferred_specials = sorted(freq, key=freq.get, reverse=True)  # type: ignore[arg-type]

    if cap_styles:
        from collections import Counter
        analysis.capitalization_style = Counter(cap_styles).most_common(1)[0][0]

    if num_styles:
        from collections import Counter
        analysis.number_style = Counter(num_styles).most_common(1)[0][0]

    return analysis
