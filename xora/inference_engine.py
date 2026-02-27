"""Derive password-relevant data that isn't explicitly stated in a profile.

This is the "thinking layer" — it reasons about profile data the way a human
red teamer would: birthday → zodiac, school → mascot, ethnicity → cultural
words, city → local slang, emotional events → anchor words.

Architecture:
  - LLM handles ALL knowledge-based inference (universities, cities, cultures,
    hobbies, vehicles, medical, etc.) — it has the knowledge, we don't need
    hardcoded tables.
  - Rule-based functions handle ONLY deterministic math: zodiac from birthday,
    date substring patterns, family name extraction.
  - Correlation analysis uses structural pattern matching on passwords (years,
    separators, cross-field co-occurrence) — no external knowledge required.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class InferredData:
    """A single piece of inferred intelligence derived from profile data."""
    word: str
    rule: str
    source: str
    confidence: float
    reasoning: str


@dataclass
class Correlation:
    """A discovered connection between passwords and profile data."""
    pattern_name: str
    evidence: list[str]
    insight: str
    confidence: float
    suggested_words: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pattern_name": self.pattern_name,
            "evidence": self.evidence,
            "insight": self.insight,
            "confidence": self.confidence,
            "suggested_words": self.suggested_words,
        }


# =========================================================================
# ZODIAC INFERENCE (deterministic — stays rule-based)
# =========================================================================

_ZODIAC_TABLE = [
    ((3, 21), (4, 19), "Aries", "fire", "ram"),
    ((4, 20), (5, 20), "Taurus", "earth", "bull"),
    ((5, 21), (6, 20), "Gemini", "air", "twins"),
    ((6, 21), (7, 22), "Cancer", "water", "crab"),
    ((7, 23), (8, 22), "Leo", "fire", "lion"),
    ((8, 23), (9, 22), "Virgo", "earth", "maiden"),
    ((9, 23), (10, 22), "Libra", "air", "scales"),
    ((10, 23), (11, 21), "Scorpio", "water", "scorpion"),
    ((11, 22), (12, 21), "Sagittarius", "fire", "archer"),
    ((12, 22), (1, 19), "Capricorn", "earth", "goat"),
    ((1, 20), (2, 18), "Aquarius", "air", "waterbearer"),
    ((2, 19), (3, 20), "Pisces", "water", "fish"),
]

_MONTH_NAMES = {
    "january": 1, "jan": 1, "february": 2, "feb": 2, "march": 3, "mar": 3,
    "april": 4, "apr": 4, "may": 5, "june": 6, "jun": 6,
    "july": 7, "jul": 7, "august": 8, "aug": 8, "september": 9, "sep": 9,
    "sept": 9, "october": 10, "oct": 10, "november": 11, "nov": 11,
    "december": 12, "dec": 12,
}


def _parse_date(date_str: str) -> tuple[int, int, int] | None:
    """Parse a date string into (month, day, year). Returns None on failure."""
    if not date_str:
        return None
    s = date_str.strip()

    m = re.match(r"(\w+)\s+(\d{1,2}),?\s*(\d{4})", s, re.IGNORECASE)
    if m:
        month_name = m.group(1).lower()
        month = _MONTH_NAMES.get(month_name)
        if month:
            return (month, int(m.group(2)), int(m.group(3)))

    m = re.match(r"(\d{1,2})\s+(\w+),?\s*(\d{4})", s, re.IGNORECASE)
    if m:
        month_name = m.group(2).lower()
        month = _MONTH_NAMES.get(month_name)
        if month:
            return (month, int(m.group(1)), int(m.group(3)))

    m = re.match(r"(\d{1,4})[/\\-.](\d{1,2})[/\\-.](\d{2,4})", s)
    if m:
        a, b, c = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if a > 31:
            return (b, c, a)
        return (a, b, c if c > 99 else c + 1900)

    return None


def _get_zodiac(month: int, day: int) -> tuple[str, str, str] | None:
    """Return (sign, element, symbol) for a given month/day."""
    for start, end, sign, element, symbol in _ZODIAC_TABLE:
        if sign == "Capricorn":
            if (month == 12 and day >= 22) or (month == 1 and day <= 19):
                return sign, element, symbol
        elif (month == start[0] and day >= start[1]) or \
             (month == end[0] and day <= end[1]):
            return sign, element, symbol
    return None


def infer_zodiac(birthdate: str) -> list[InferredData]:
    """Derive zodiac sign from birthdate."""
    parsed = _parse_date(birthdate)
    if not parsed:
        return []
    month, day, _ = parsed
    zodiac = _get_zodiac(month, day)
    if not zodiac:
        return []
    sign, element, _ = zodiac
    return [
        InferredData(
            word=sign, rule="zodiac", source=f"birthdate: {birthdate}",
            confidence=0.7,
            reasoning=f"Born {birthdate} = {sign}; people often identify "
                      f"with their zodiac sign",
        ),
        InferredData(
            word=element, rule="zodiac", source=f"birthdate: {birthdate}",
            confidence=0.3,
            reasoning=f"{sign} is a {element} sign",
        ),
    ]


# =========================================================================
# BIRTHDAY PATTERN INFERENCE (deterministic — stays rule-based)
# =========================================================================

def infer_birthday_patterns(birthdate: str) -> list[InferredData]:
    """Extract date substrings people commonly use in passwords."""
    parsed = _parse_date(birthdate)
    if not parsed:
        return []
    month, day, year = parsed
    results: list[InferredData] = []
    src = f"birthdate: {birthdate}"

    patterns = {
        f"{month:02d}{day:02d}": "MMDD",
        f"{day:02d}{month:02d}": "DDMM",
        f"{month}{day}": "MD (no padding)",
        str(year): "full birth year",
        str(year % 100): "2-digit birth year",
    }
    for pattern, desc in patterns.items():
        results.append(InferredData(
            word=pattern, rule="birthday_pattern", source=src,
            confidence=0.8, reasoning=f"{desc} — extremely common in passwords",
        ))

    month_names = [
        k for k, v in _MONTH_NAMES.items() if v == month and len(k) >= 3
    ]
    if month_names:
        short = month_names[0].capitalize()
        results.append(InferredData(
            word=short, rule="birthday_pattern", source=src,
            confidence=0.4, reasoning="Month abbreviation",
        ))

    return results


# =========================================================================
# FAMILY ANCHOR INFERENCE (structural — stays rule-based)
# =========================================================================

def infer_family_anchors(profile_data: dict) -> list[InferredData]:
    """Derive emotionally significant words from family relationships."""
    results: list[InferredData] = []

    partner = profile_data.get("partner_name", "")
    if partner:
        first = partner.split()[0] if partner.split() else partner
        results.append(InferredData(
            word=first, rule="family_anchor", source=f"partner: {partner}",
            confidence=0.8,
            reasoning="Partner's first name — high probability password word",
        ))

    for pet in profile_data.get("pet_names", []):
        results.append(InferredData(
            word=pet, rule="family_anchor", source=f"pet: {pet}",
            confidence=0.9,
            reasoning="Pet name — one of the most common password words",
        ))

    for child in profile_data.get("children_names", []):
        if not child or child.lower() in ("none", "n/a", "no", "unknown"):
            continue
        first = child.split()[0] if child.split() else child
        results.append(InferredData(
            word=first, rule="family_anchor", source=f"child: {child}",
            confidence=0.9,
            reasoning="Child's name — extremely common in passwords",
        ))

    return results


# =========================================================================
# YEAR EXTRACTION (structural — stays rule-based)
# =========================================================================

def infer_years_from_profile(profile_data: dict) -> list[InferredData]:
    """Extract meaningful years from education, work, and life events."""
    results: list[InferredData] = []
    seen: set[str] = set()

    all_text = " ".join(str(v) for v in profile_data.get("extra_words", []))
    all_text += " " + " ".join(str(v) for v in profile_data.get("interests", []))
    all_text += " " + " ".join(str(v) for v in profile_data.get("companies", []))
    all_text += " " + " ".join(str(v) for v in profile_data.get("important_dates", []))

    edu_keywords = [
        "university", "college", "institute", "school",
        "b.s.", "b.a.", "m.s.", "m.a.", "ph.d", "mba",
        "degree", "graduated", "class of",
    ]

    for w in profile_data.get("extra_words", []):
        year_match = re.search(r"\b(19|20)\d{2}\b", w)
        if year_match and any(kw in w.lower() for kw in edu_keywords):
            year = year_match.group()
            if year not in seen:
                seen.add(year)
                short_year = year[2:]
                results.append(InferredData(
                    word=year, rule="graduation_year", source=f"education: {w}",
                    confidence=0.8,
                    reasoning="Graduation year — commonly used in passwords",
                ))
                if short_year not in seen:
                    seen.add(short_year)
                    results.append(InferredData(
                        word=short_year, rule="graduation_year",
                        source=f"education: {w}",
                        confidence=0.7,
                        reasoning="2-digit graduation year",
                    ))

    return results


# =========================================================================
# MAIN INFERENCE ORCHESTRATOR
# =========================================================================

def run_inference(profile_data: dict) -> list[InferredData]:
    """Run rule-based inference — deterministic math only.

    This is the fallback when no LLM is available. It handles:
      - Zodiac sign from birthday
      - Birthday date patterns (MMDD, year, etc.)
      - Family anchors (partner, pet, child names)
      - Year extraction from education strings

    Everything else (universities, cities, cultures, hobbies, vehicles,
    medical) requires knowledge the LLM has but we don't hardcode.
    """
    results: list[InferredData] = []

    results.extend(infer_zodiac(profile_data.get("birthdate", "")))
    results.extend(infer_birthday_patterns(profile_data.get("birthdate", "")))
    results.extend(infer_family_anchors(profile_data))
    results.extend(infer_years_from_profile(profile_data))

    # Deduplicate by word (keep highest confidence)
    seen: dict[str, InferredData] = {}
    for item in results:
        key = item.word.lower()
        if key not in seen or item.confidence > seen[key].confidence:
            seen[key] = item
    return list(seen.values())


def run_inference_llm(
    profile_data: dict, provider, *, fallback: bool = True
) -> list[InferredData]:
    """Run LLM-powered inference, then supplement with rule-based results.

    The LLM does all knowledge-based reasoning (mascots, city slang, cultural
    words, hobby terms, medical shorthand, vehicle culture, etc.).
    Rule-based functions fill in deterministic items the LLM might skip
    (zodiac math, date substring patterns).
    """
    results: list[InferredData] = []

    try:
        llm_inferred = provider.infer_from_profile(profile_data)
        if llm_inferred:
            for item in llm_inferred:
                results.append(InferredData(
                    word=item.get("word", ""),
                    rule=item.get("rule", "llm_inference"),
                    source=item.get("source", ""),
                    confidence=item.get("confidence", 0.5),
                    reasoning=item.get("reasoning", ""),
                ))
    except Exception:
        pass

    if fallback or not results:
        rule_based = run_inference(profile_data)
        existing_words = {r.word.lower() for r in results}
        for item in rule_based:
            if item.word.lower() not in existing_words:
                results.append(item)

    return results


# =========================================================================
# CORRELATION ANALYSIS (structural pattern matching — stays rule-based)
# =========================================================================

def find_correlations(
    decoded_passwords: list[dict],
    profile_data: dict,
    inferred: list[InferredData],
) -> list[Correlation]:
    """Find hidden connections between passwords and profile data.

    Uses structural analysis only — no external knowledge required.
    """
    correlations: list[Correlation] = []

    # 1. Year overlap: years in passwords that map to profile events
    password_years: dict[str, list[str]] = {}
    for pw_data in decoded_passwords:
        orig = pw_data.get("original", "")
        for match in re.finditer(r"\b(19|20)\d{2}\b", orig):
            year = match.group()
            password_years.setdefault(year, []).append(orig)

    profile_years: dict[str, list[str]] = {}
    all_profile_text = " ".join(
        str(v) for v in profile_data.values() if isinstance(v, str)
    )
    for vals in profile_data.values():
        if isinstance(vals, list):
            all_profile_text += " " + " ".join(str(v) for v in vals)

    for match in re.finditer(r"\b(19|20)\d{2}\b", all_profile_text):
        year = match.group()
        context = all_profile_text[
            max(0, match.start() - 40):match.end() + 40
        ].strip()
        profile_years.setdefault(year, []).append(context)

    for year, pw_list in password_years.items():
        if year in profile_years:
            contexts = profile_years[year]
            correlations.append(Correlation(
                pattern_name="shared_year",
                evidence=[f"Password: {p}" for p in pw_list] +
                         [f"Profile: {c}" for c in contexts[:3]],
                insight=f"Year {year} appears in both passwords and profile — "
                        f"emotionally significant, not random",
                confidence=0.8,
                suggested_words=[year, year[2:]],
            ))

        if len(pw_list) >= 2:
            correlations.append(Correlation(
                pattern_name="year_reuse",
                evidence=[f"Used in: {p}" for p in pw_list],
                insight=f"Year {year} used in {len(pw_list)} passwords — "
                        f"this number has special significance",
                confidence=0.9,
                suggested_words=[year, year[2:]],
            ))

    # 2. Separator fingerprint
    sep_counts: Counter[str] = Counter()
    for pw_data in decoded_passwords:
        orig = pw_data.get("original", "")
        for c in orig:
            if not c.isalnum():
                sep_counts[c] += 1

    if sep_counts:
        total_seps = sum(sep_counts.values())
        used = [(c, n) for c, n in sep_counts.most_common()]
        never_used = [c for c in "!@#$%^&*_-" if c not in sep_counts]

        if used and never_used:
            correlations.append(Correlation(
                pattern_name="separator_fingerprint",
                evidence=[
                    f"'{c}' used {n}x ({n / total_seps:.0%})"
                    for c, n in used[:5]
                ],
                insight=f"Target prefers "
                        f"{', '.join(repr(c) for c, _ in used[:3])} "
                        f"as separators; never uses "
                        f"{', '.join(repr(c) for c in never_used[:3])}",
                confidence=0.85,
                suggested_words=[],
            ))

    # 3. Cross-field co-occurrence in passwords
    profile_words_by_field: dict[str, set[str]] = {}
    for field_name in ["pet_names", "interests", "extra_words", "companies",
                       "children_names", "nicknames"]:
        for w in profile_data.get(field_name, []):
            for token in w.lower().split():
                if len(token) >= 3:
                    profile_words_by_field.setdefault(
                        token, set()
                    ).add(field_name)

    for key in ["first_name", "last_name", "partner_name"]:
        val = profile_data.get(key, "")
        if val:
            for token in val.lower().split():
                if len(token) >= 3:
                    profile_words_by_field.setdefault(
                        token, set()
                    ).add(key)

    for pw_data in decoded_passwords:
        words = [w.lower() for w in pw_data.get("words", [])]
        fields_in_pw: set[str] = set()
        matched_words: list[str] = []
        for word in words:
            if word in profile_words_by_field:
                fields_in_pw.update(profile_words_by_field[word])
                matched_words.append(word)

        if len(fields_in_pw) >= 2:
            correlations.append(Correlation(
                pattern_name="cross_field_combo",
                evidence=[
                    f"Password: {pw_data.get('original', '')}",
                    f"Words from: {', '.join(fields_in_pw)}",
                    f"Matched: {', '.join(matched_words)}",
                ],
                insight=f"This password combines data from {len(fields_in_pw)} "
                        f"different profile sections — the target mixes "
                        f"categories",
                confidence=0.7,
                suggested_words=[],
            ))

    # 4. Place-based trajectory (generic — no city table needed)
    #    Detect "X2Y" or "X_to_Y" patterns in passwords where X and Y are
    #    both words found in the profile (cities, schools, etc.)
    profile_place_words: set[str] = set()
    for w in profile_data.get("extra_words", []):
        for token in w.split():
            clean = token.strip("(),.-").lower()
            if len(clean) >= 3 and clean.isalpha():
                profile_place_words.add(clean)

    for pw_data in decoded_passwords:
        orig = pw_data.get("original", "")
        traj_match = re.search(
            r"([A-Za-z]{3,})2([A-Za-z]{3,})", orig
        )
        if traj_match:
            from_place = traj_match.group(1).lower()
            to_place = traj_match.group(2).lower()
            from_in_profile = from_place in profile_place_words
            to_in_profile = to_place in profile_place_words
            if from_in_profile or to_in_profile:
                combos = [
                    f"{traj_match.group(2)}2{traj_match.group(1)}",
                ]
                correlations.append(Correlation(
                    pattern_name="life_trajectory",
                    evidence=[
                        f"Password: {orig}",
                        f"Pattern: {traj_match.group(1)} → "
                        f"{traj_match.group(2)}",
                    ],
                    insight="Target encodes place-to-place movement in "
                            "passwords — generate reversed and alternate "
                            "city combos",
                    confidence=0.85,
                    suggested_words=combos,
                ))

    # 5. Category confirmation from passwords
    confirmed_categories: set[str] = set()
    for pw_data in decoded_passwords:
        words = pw_data.get("words", [])
        for word in words:
            low = word.lower()
            for inf in inferred:
                if inf.word.lower() == low:
                    confirmed_categories.add(inf.rule)

    if confirmed_categories:
        correlations.append(Correlation(
            pattern_name="category_confirmation",
            evidence=[
                f"Confirmed rule: {cat}" for cat in confirmed_categories
            ],
            insight=f"Password analysis confirms these inference categories: "
                    f"{', '.join(confirmed_categories)}. "
                    f"Boost confidence for all words from these rules.",
            confidence=0.9,
            suggested_words=[],
        ))

    return correlations


def find_correlations_llm(
    decoded_passwords: list[dict],
    profile_data: dict,
    inferred: list[InferredData],
    provider,
    *,
    fallback: bool = True,
) -> list[Correlation]:
    """Run LLM-powered correlation analysis, supplemented by rule-based checks."""
    correlations: list[Correlation] = []

    try:
        inferred_dicts = [
            {"word": i.word, "rule": i.rule, "source": i.source,
             "reasoning": i.reasoning}
            for i in inferred
        ]
        llm_corrs = provider.correlate_passwords_and_profile(
            decoded_passwords, profile_data, inferred_dicts
        )
        if llm_corrs:
            for c in llm_corrs:
                correlations.append(Correlation(
                    pattern_name=c.get("pattern_name", "llm_insight"),
                    evidence=c.get("evidence", []),
                    insight=c.get("insight", ""),
                    confidence=c.get("confidence", 0.7),
                    suggested_words=c.get("suggested_words", []),
                ))
    except Exception:
        pass

    if fallback or not correlations:
        rule_corrs = find_correlations(
            decoded_passwords, profile_data, inferred
        )
        existing = {c.pattern_name for c in correlations}
        for c in rule_corrs:
            if c.pattern_name not in existing:
                correlations.append(c)

    return correlations
