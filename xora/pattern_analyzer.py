"""Analyze known passwords to detect structural patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from xora.password_profiler import deleet


# ============================================================================
# DERIVATION CHAIN DETECTION
# ============================================================================

@dataclass
class DerivationChain:
    """A group of passwords that share a base word and form a progression.

    Two chain types:
      policy_ratchet  — base → base+num → base+num+special
                        User adding complexity one class at a time (policy forced)
      sequential_enum — base+1 → base+2 → base+3
                        User cycling through accounts/resets with a counter
    """
    chain_type: str          # "policy_ratchet" | "sequential_enum"
    base_word: str           # the decoded root word shared by all members
    members: list[str]       # original passwords in order
    templates: list[str]     # structural template for each member
    next_likely: list[str]   # predicted next passwords in the sequence

    def to_dict(self) -> dict:
        return {
            "chain_type": self.chain_type,
            "base_word": self.base_word,
            "members": self.members,
            "templates": self.templates,
            "next_likely": self.next_likely,
        }


def _extract_base_and_suffix(password: str) -> tuple[str, str]:
    """Split a password into (alpha_base, non_alpha_suffix).

    Uses the raw password's leading alphabetic run (lowercased) as the base
    so that digit/special suffixes (1, !, 123) are preserved intact for
    sequential comparisons. Leet-only alpha substitutions (@ → a, 3 → e) in
    the middle of a word are normalised via a lightweight inline pass.
    """
    # Only normalise characters that unambiguously substitute letters.
    # Digits (1, 3, 4, 5, 7, 0) and punctuation (!, @, $) are left intact
    # so they land in the suffix and sequential counters remain intact.
    _LEET_ALPHA: dict[str, str] = {"€": "e"}
    normalised = []
    for c in password:
        if c.isalpha():
            normalised.append(c.lower())
        elif c in _LEET_ALPHA:
            normalised.append(_LEET_ALPHA[c])
        else:
            normalised.append(c)
    pw_norm = "".join(normalised)

    # Extract leading alpha run as the base, remainder as suffix
    match = re.match(r"^([a-z]+)(.*)", pw_norm, re.IGNORECASE)
    if match:
        return match.group(1).lower(), match.group(2)
    return pw_norm.lower(), ""


def detect_derivation_chains(passwords: list[str]) -> list[DerivationChain]:
    """Detect policy_ratchet and sequential_enum chains in a password list.

    Scans all pairs to find passwords sharing the same decoded alpha base,
    then classifies the group as a ratchet (growing complexity) or
    sequential enumeration (incrementing counter).
    """
    if len(passwords) < 2:
        return []

    # Group passwords by decoded alpha base
    base_groups: dict[str, list[str]] = {}
    for pw in passwords:
        base, _ = _extract_base_and_suffix(pw)
        if len(base) < 3:
            continue
        base_groups.setdefault(base, []).append(pw)

    chains: list[DerivationChain] = []

    for base, group in base_groups.items():
        if len(group) < 2:
            continue

        # Sort by length so chains are naturally ordered shortest → longest
        group_sorted = sorted(group, key=len)

        def _norm(pw: str) -> str:
            """Lowercase, strip spaces; keep digits/specials intact for prefix comparison."""
            return pw.lower().replace(" ", "").replace("€", "e")

        # --- Check for policy ratchet ---
        # Ratchet: each member is a prefix of the next (or close to it)
        # and adds at least one new character class
        ratchet: list[str] = [group_sorted[0]]
        for pw in group_sorted[1:]:
            prev = ratchet[-1]
            norm_prev = _norm(prev)
            norm_pw = _norm(pw)
            if norm_pw.startswith(norm_prev) and len(norm_pw) > len(norm_prev):
                ratchet.append(pw)

        if len(ratchet) >= 2:
            templates = [analyze_password(pw).template for pw in ratchet]
            # Predict: take last member and generate +digit, +special variants
            last_decoded = deleet(ratchet[-1]).replace(" ", "")
            next_likely = []
            if not any(c.isdigit() for c in last_decoded):
                next_likely += [ratchet[-1] + s for s in ["1", "2", "123"]]
            if all(c.isalnum() for c in last_decoded):
                next_likely += [ratchet[-1] + s for s in ["!", "@", "#"]]
            chains.append(DerivationChain(
                chain_type="policy_ratchet",
                base_word=base,
                members=ratchet,
                templates=templates,
                next_likely=next_likely[:5],
            ))
            continue  # don't also check sequential for this group

        # --- Check for sequential enumeration ---
        # Sequential: all members match {base}{single_digit_or_small_int}
        # and the numbers form a consecutive or near-consecutive run
        seq_pattern = re.compile(r"^(.+?)(\d{1,3})([^a-zA-Z0-9]*)$")
        numbered: list[tuple[int, str]] = []  # (number, original_password)
        suffix_specials: set[str] = set()

        for pw in group:
            # match on lowercased password to get the actual trailing suffix
            m = seq_pattern.match(pw.lower())
            if m and m.group(1).lower() == base:
                try:
                    n = int(m.group(2))
                    numbered.append((n, pw))
                    if m.group(3):
                        suffix_specials.add(m.group(3))
                except ValueError:
                    pass

        if len(numbered) >= 2:
            numbered.sort(key=lambda x: x[0])
            nums = [n for n, _ in numbered]
            members = [pw for _, pw in numbered]
            templates = [analyze_password(pw).template for pw in members]

            # Predict next numbers in sequence
            last_n = nums[-1]
            gap = nums[-1] - nums[0]
            step = 1 if len(nums) < 3 else round((nums[-1] - nums[0]) / (len(nums) - 1))
            step = max(1, step)
            next_nums = [last_n + step * i for i in range(1, 4)]
            # Use same trailing specials pattern as observed
            spec = next(iter(suffix_specials), "")
            next_likely = [f"{base}{n}{spec}" for n in next_nums]

            # Also predict: reset to 0, jump to round numbers
            for extra in [0, 10, 100]:
                candidate = f"{base}{extra}{spec}"
                if candidate not in next_likely:
                    next_likely.append(candidate)

            chains.append(DerivationChain(
                chain_type="sequential_enum",
                base_word=base,
                members=members,
                templates=templates,
                next_likely=next_likely[:8],
            ))

    return chains


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


def _classify_cap_pattern(word: str) -> str:
    """Return the capitalization pattern of a single alpha word.

    Patterns:
      all_lower   — all letters lowercase:  password
      all_upper   — all letters uppercase:  ACDC, RATT
      first_only  — only first letter upper: Password, Motley
      camel       — interior capital follows a lowercase (MotleyCrue, VanHalen)
      alternating — evenly-spaced caps (pAsSwOrD)
      mixed       — anything else
    """
    alpha = [c for c in word if c.isalpha()]
    if not alpha:
        return "all_lower"

    upper_count = sum(1 for c in alpha if c.isupper())
    if upper_count == 0:
        return "all_lower"
    if upper_count == len(alpha):
        return "all_upper"
    if upper_count == 1 and alpha[0].isupper():
        return "first_only"

    # Alternating: upper positions are evenly spaced — check before camel
    # so pAsSwOrD isn't misclassified as camel (which also has lc→uc transitions)
    upper_pos = [i for i, c in enumerate(alpha) if c.isupper()]
    if len(upper_pos) >= 3:
        diffs = [upper_pos[i + 1] - upper_pos[i] for i in range(len(upper_pos) - 1)]
        if len(set(diffs)) == 1:
            return "alternating"

    # CamelCase: at least one lowercase→uppercase transition inside the word
    has_camel = any(
        alpha[i].islower() and alpha[i + 1].isupper()
        for i in range(len(alpha) - 1)
    )
    if has_camel:
        return "camel"

    return "mixed"


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
    derivation_chains: list[DerivationChain] = field(default_factory=list)
    cap_patterns: dict[str, int] = field(default_factory=dict)

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
        if self.derivation_chains:
            d["derivation_chains"] = [c.to_dict() for c in self.derivation_chains]
        if self.cap_patterns:
            d["cap_patterns"] = self.cap_patterns
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

        # Analyze capitalization — both aggregate style and per-pattern counts
        words = _WORD_RE.findall(pw)
        for w in words:
            if len(w) < 2:
                continue
            if w[0].isupper() and (len(w) == 1 or w[1:].islower()):
                cap_styles.append("capitalize")
            elif w.isupper():
                cap_styles.append("upper")
            elif w.islower():
                cap_styles.append("lower")
            else:
                cap_styles.append("mixed")

            # Per-pattern frequency count for weighted generation
            pattern = _classify_cap_pattern(w)
            analysis.cap_patterns[pattern] = analysis.cap_patterns.get(pattern, 0) + 1

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

    analysis.derivation_chains = detect_derivation_chains(passwords)

    return analysis
