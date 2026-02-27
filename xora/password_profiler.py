"""Decode leet speak, categorize passwords, and build a behavioral profile."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field


# =========================================================================
# LEET SPEAK DECODER
# =========================================================================

_LEET_TO_ALPHA: dict[str, str] = {
    "0": "o",
    "1": "il",   # ambiguous: could be i or l
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
    "|": "l",
    "+": "t",
    "(": "c",
    "€": "e",
    "¡": "i",
}

# For ambiguous mappings (1 -> i or l), try the more common "i" first
_LEET_PRIMARY: dict[str, str] = {k: v[0] for k, v in _LEET_TO_ALPHA.items()}


def deleet(password: str) -> str:
    """Decode leet speak in a password back to probable plaintext.

    Only decodes leet characters when they're embedded in word context
    (adjacent to alpha chars). Trailing/leading specials used as
    punctuation (!@#$ at boundaries) and digit runs (years like 1980)
    are preserved as-is.
    """
    chars = list(password)
    n = len(chars)
    result = []

    i = 0
    while i < n:
        c = chars[i]

        if c in ("_", "-"):
            result.append(" ")
            i += 1
            continue

        # Check if this is a digit run (2+ consecutive digits) — keep as-is
        if c.isdigit():
            j = i
            while j < n and chars[j].isdigit():
                j += 1
            run = password[i:j]
            if len(run) >= 2:
                result.append(run)
                i = j
                continue
            # Single digit: decode only if surrounded by alpha
            has_alpha_before = (i > 0 and (chars[i - 1].isalpha()
                                           or chars[i - 1] in _LEET_PRIMARY))
            has_alpha_after = (i + 1 < n and (chars[i + 1].isalpha()
                                              or chars[i + 1] in _LEET_PRIMARY))
            if has_alpha_before or has_alpha_after:
                if c in _LEET_PRIMARY:
                    result.append(_LEET_PRIMARY[c])
                else:
                    result.append(c)
            else:
                result.append(c)
            i += 1
            continue

        # Special chars: decode only if embedded between alpha-like chars
        if c in _LEET_PRIMARY and not c.isalpha():
            has_alpha_before = (i > 0 and (chars[i - 1].isalpha()
                                           or chars[i - 1] in _LEET_PRIMARY))
            has_alpha_after = (i + 1 < n and (chars[i + 1].isalpha()
                                              or chars[i + 1] in _LEET_PRIMARY))
            if has_alpha_before and has_alpha_after:
                result.append(_LEET_PRIMARY[c])
            else:
                result.append(c)
            i += 1
            continue

        result.append(c)
        i += 1

    decoded = "".join(result)
    decoded = re.sub(r"\s+", " ", decoded).strip()
    return decoded


def deleet_to_words(password: str) -> list[str]:
    """Decode a password and extract individual words from it.

    Splits on CamelCase boundaries, separators, and transitions between
    alpha and numeric runs. Filters out pure numbers and very short tokens.
    """
    decoded = deleet(password)

    # Split CamelCase: "MotleyCrue" -> ["Motley", "Crue"]
    words = re.sub(r"([a-z])([A-Z])", r"\1 \2", decoded)
    # Split on non-alpha
    tokens = re.split(r"[^a-zA-Z]+", words)
    return [t for t in tokens if len(t) >= 2]


# =========================================================================
# RULE-BASED KEYWORD CATEGORIZER (fallback when no LLM)
# =========================================================================

_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "music": [
        "motley", "crue", "crew", "acdc", "ozzy", "ozbourne", "osbourne",
        "halen", "poison", "ratt", "whitesnake", "snake", "guns", "roses",
        "leppard", "leopard", "dokken", "twisted", "sister", "metallica",
        "sabbath", "zeppelin", "floyd", "beatles", "nirvana", "slayer",
        "megadeth", "maiden", "priest", "scorpions", "bon", "iver",
        "radiohead", "thief", "guitar", "rock", "roll", "metal", "punk",
        "band", "song", "music", "concert", "tour", "album", "vinyl",
        "bass", "drums", "slash", "jump", "pour", "sugar", "jungle",
        "welcome", "breakin", "round", "again", "here", "back", "black",
        "bark", "moon", "catch", "live", "highway", "thunder",
        "crime", "junkie", "podcast",
    ],
    "sports": [
        "football", "soccer", "baseball", "basketball", "hockey", "nfl",
        "nba", "mlb", "nhl", "fifa", "goal", "score", "team", "coach",
        "player", "champion", "league", "bowl", "cup", "series", "mvp",
        "run", "trail", "marathon", "sprint",
    ],
    "gaming": [
        "game", "gamer", "xbox", "playstation", "nintendo", "steam",
        "fortnite", "minecraft", "zelda", "mario", "sonic", "pokemon",
        "league", "legends", "warcraft", "overwatch", "valorant", "apex",
        "quest", "hero", "dragon", "sword", "warrior", "knight", "mage",
        "level", "noob", "pwn",
    ],
    "tech": [
        "hack", "hacker", "cyber", "code", "coder", "admin", "root",
        "linux", "python", "java", "sudo", "shell", "server", "network",
        "crypto", "data", "cloud", "devops", "redteam", "blue", "pentest",
        "exploit", "binary", "pixel",
    ],
    "nature": [
        "forest", "park", "mountain", "river", "ocean", "lake", "beach",
        "sun", "moon", "star", "wolf", "bear", "eagle", "hawk", "fox",
        "tree", "flower", "garden", "trail", "rain", "snow", "storm",
        "thunder", "lightning", "wild",
    ],
    "places": [
        "portland", "pdx", "seattle", "duluth", "iceland", "norway",
        "denver", "austin", "brooklyn", "chicago", "boston", "miami",
        "london", "paris", "tokyo", "berlin", "nyc", "vegas",
        "california", "texas", "oregon", "hawaii",
    ],
    "family": [
        "biscuit", "buddy", "max", "bella", "luna", "charlie", "daisy",
        "love", "lover", "baby", "babe", "honey", "darling", "angel",
        "family", "mom", "dad", "papa", "mama", "brother", "sister",
        "son", "daughter", "wife", "husband", "partner", "neighbor",
    ],
    "food_drink": [
        "sourdough", "coffee", "beer", "wine", "whiskey", "bourbon",
        "pizza", "taco", "burger", "bacon", "cookie", "cake",
        "chocolate", "vanilla", "sugar", "spice", "thrift", "find",
        "bake", "cook", "chef", "kitchen", "recipe",
    ],
    "health": [
        "sertraline", "lexapro", "zoloft", "prozac", "health", "clinic",
        "therapy", "yoga", "fitness", "gym", "crossfit", "meditation",
        "vegan", "keto", "diet", "wellness",
    ],
    "dates_numbers": [
        # detected dynamically, not keyword-based
    ],
    "pop_culture": [
        "marvel", "batman", "superman", "starwars", "jedi", "sith",
        "hobbit", "gandalf", "potter", "dumbledore", "avengers",
        "disney", "pixar", "anime", "manga", "naruto", "goku",
    ],
}


def _categorize_by_keywords(words: list[str]) -> list[str]:
    """Assign categories to a list of decoded words using keyword matching."""
    categories: list[str] = []
    for word in words:
        low = word.lower()
        matched = False
        for category, keywords in _CATEGORY_KEYWORDS.items():
            if low in keywords or any(kw in low for kw in keywords if len(kw) >= 4):
                categories.append(category)
                matched = True
                break
        if not matched:
            if word.isdigit():
                categories.append("dates_numbers")
            else:
                categories.append("unknown")
    return categories


# =========================================================================
# PASSWORD CATEGORIZATION
# =========================================================================

@dataclass
class CategorizedPassword:
    """A password with its decoded form and assigned category."""
    original: str
    decoded: str
    words: list[str]
    category: str
    confidence: float = 0.0


@dataclass
class PasswordProfile:
    """Behavioral profile of a target's password habits.

    Built from analyzing and categorizing known passwords to understand
    what themes, topics, and patterns the target gravitates toward.
    """
    categorized: list[CategorizedPassword] = field(default_factory=list)
    category_distribution: dict[str, float] = field(default_factory=dict)
    top_categories: list[str] = field(default_factory=list)
    total_passwords: int = 0
    structural_habits: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "categorized_passwords": [
                {
                    "original": cp.original,
                    "decoded": cp.decoded,
                    "words": cp.words,
                    "category": cp.category,
                    "confidence": cp.confidence,
                }
                for cp in self.categorized
            ],
            "category_distribution": self.category_distribution,
            "top_categories": self.top_categories,
            "total_passwords": self.total_passwords,
            "structural_habits": self.structural_habits,
        }


def categorize_passwords_rule_based(
    passwords: list[str],
) -> list[CategorizedPassword]:
    """Categorize passwords using leet decoding + keyword matching.

    Fallback when no LLM is available.
    """
    results: list[CategorizedPassword] = []
    for pw in passwords:
        decoded = deleet(pw)
        words = deleet_to_words(pw)
        categories = _categorize_by_keywords(words)
        # Pick the most frequent non-unknown category
        cat_counts = Counter(c for c in categories if c != "unknown")
        if cat_counts:
            category = cat_counts.most_common(1)[0][0]
            confidence = cat_counts[category] / len(categories)
        else:
            category = "unknown"
            confidence = 0.0
        results.append(CategorizedPassword(
            original=pw,
            decoded=decoded,
            words=words,
            category=category,
            confidence=confidence,
        ))
    return results


def build_password_profile(
    categorized: list[CategorizedPassword],
    structural_habits: dict[str, str] | None = None,
) -> PasswordProfile:
    """Build a behavioral profile from categorized passwords.

    Computes the category distribution and ranks top themes.
    """
    profile = PasswordProfile()
    profile.categorized = categorized
    profile.total_passwords = len(categorized)

    if not categorized:
        return profile

    # Count categories
    cat_counts = Counter(cp.category for cp in categorized)
    total = len(categorized)
    profile.category_distribution = {
        cat: round(count / total, 3)
        for cat, count in cat_counts.most_common()
    }
    profile.top_categories = [cat for cat, _ in cat_counts.most_common()
                               if cat != "unknown"]

    if structural_habits:
        profile.structural_habits = structural_habits

    return profile


def cross_reference_profile(
    pw_profile: PasswordProfile,
    profile_data: dict,
) -> dict[str, float]:
    """Cross-reference password categories with the user's profile data.

    Returns a priority weight for each category: categories that appear
    in BOTH the passwords AND the profile get boosted, while categories
    only in the profile get demoted.
    """
    weights: dict[str, float] = {}

    # Start with password category distribution as base weights
    for cat, pct in pw_profile.category_distribution.items():
        weights[cat] = pct

    # Gather profile words for cross-reference
    profile_words: set[str] = set()
    for key in ["interests", "extra_words", "teams", "companies",
                "pet_names", "nicknames", "children_names"]:
        for w in profile_data.get(key, []):
            profile_words.update(w.lower().split())
    for key in ["first_name", "last_name", "partner_name"]:
        val = profile_data.get(key, "")
        if val:
            profile_words.update(val.lower().split())

    # Boost categories that have evidence in both passwords AND profile
    for cp in pw_profile.categorized:
        for word in cp.words:
            if word.lower() in profile_words:
                cat = cp.category
                weights[cat] = weights.get(cat, 0) + 0.05

    # Check for profile categories NOT in passwords (lower priority)
    profile_categories = _categorize_by_keywords(list(profile_words))
    for cat in set(profile_categories):
        if cat not in weights and cat != "unknown":
            weights[cat] = 0.05  # low priority: in profile but not passwords

    # Normalize to sum=1.0
    total = sum(weights.values())
    if total > 0:
        weights = {k: round(v / total, 3) for k, v in weights.items()}

    return dict(sorted(weights.items(), key=lambda x: x[1], reverse=True))


# =========================================================================
# PASSWORD STRENGTH ANALYSIS
# =========================================================================

_COMMON_PASSWORDS: set[str] = {
    "password", "123456", "qwerty", "letmein", "admin", "welcome",
    "monkey", "dragon", "master", "login", "abc123", "iloveyou",
    "trustno1", "sunshine", "princess", "football", "shadow", "superman",
    "michael", "password1", "12345678",
}


@dataclass
class PasswordStrength:
    """Strength assessment for a single password."""
    password: str
    score: float  # 0.0 (trivial) to 1.0 (fortress)
    tier: str  # weak, moderate, strong
    length: int
    char_classes: int  # how many of: upper, lower, digit, special
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    has_leet: bool
    entropy_bits: float
    weaknesses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "password": self.password,
            "score": round(self.score, 2),
            "tier": self.tier,
            "length": self.length,
            "char_classes": self.char_classes,
            "has_upper": self.has_upper,
            "has_lower": self.has_lower,
            "has_digit": self.has_digit,
            "has_special": self.has_special,
            "has_leet": self.has_leet,
            "entropy_bits": round(self.entropy_bits, 1),
            "weaknesses": self.weaknesses,
        }


@dataclass
class StrengthProfile:
    """Aggregate strength assessment across all known passwords."""
    tier: str  # weak, moderate, strong
    avg_score: float
    avg_length: float
    avg_char_classes: float
    avg_entropy: float
    min_length: int
    max_length: int
    reuse_ratio: float  # fraction of passwords sharing base words
    leet_usage_pct: float
    always_has_upper: bool
    always_has_lower: bool
    always_has_digit: bool
    always_has_special: bool
    common_weaknesses: list[str] = field(default_factory=list)
    individual: list[PasswordStrength] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tier": self.tier,
            "avg_score": round(self.avg_score, 2),
            "avg_length": round(self.avg_length, 1),
            "avg_char_classes": round(self.avg_char_classes, 1),
            "avg_entropy": round(self.avg_entropy, 1),
            "min_length": self.min_length,
            "max_length": self.max_length,
            "reuse_ratio": round(self.reuse_ratio, 2),
            "leet_usage_pct": round(self.leet_usage_pct, 2),
            "always_has_upper": self.always_has_upper,
            "always_has_lower": self.always_has_lower,
            "always_has_digit": self.always_has_digit,
            "always_has_special": self.always_has_special,
            "common_weaknesses": self.common_weaknesses,
            "individual": [s.to_dict() for s in self.individual],
        }


def _estimate_entropy(password: str) -> float:
    """Estimate Shannon entropy in bits."""
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(not c.isalnum() for c in password):
        charset_size += 32
    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def score_password_strength(password: str) -> PasswordStrength:
    """Score a single password's strength on a 0-1 scale."""
    weaknesses: list[str] = []

    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    char_classes = sum([has_upper, has_lower, has_digit, has_special])

    decoded = deleet(password)
    has_leet = decoded.lower() != password.lower()

    entropy = _estimate_entropy(password)

    # --- Scoring ---
    score = 0.0

    # Length contribution (0-0.3)
    if length >= 16:
        score += 0.3
    elif length >= 12:
        score += 0.2
    elif length >= 8:
        score += 0.1
    else:
        weaknesses.append("very_short")

    if length < 8:
        weaknesses.append("under_8_chars")

    # Char class diversity (0-0.25)
    score += char_classes * 0.0625  # 4 classes = 0.25

    if not has_upper:
        weaknesses.append("no_uppercase")
    if not has_lower:
        weaknesses.append("no_lowercase")
    if not has_digit:
        weaknesses.append("no_digit")
    if not has_special:
        weaknesses.append("no_special")

    # Entropy contribution (0-0.25)
    if entropy >= 60:
        score += 0.25
    elif entropy >= 45:
        score += 0.18
    elif entropy >= 30:
        score += 0.1
    else:
        weaknesses.append("low_entropy")

    # Leet speak bonus (0.05) — shows sophistication
    if has_leet:
        score += 0.05

    # Pattern penalties
    if password.lower() in _COMMON_PASSWORDS:
        score = max(score - 0.3, 0.0)
        weaknesses.append("common_password")

    # Sequential/repeated chars
    if re.search(r"(.)\1{2,}", password):
        score = max(score - 0.05, 0.0)
        weaknesses.append("repeated_chars")

    if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde)", password.lower()):
        score = max(score - 0.05, 0.0)
        weaknesses.append("sequential_chars")

    # Multi-word structure bonus (0.1) — compound passwords are harder
    word_parts = re.findall(r"[A-Za-z]{2,}", password)
    if len(word_parts) >= 2:
        score += 0.1
    elif len(word_parts) == 1 and length < 10:
        weaknesses.append("single_word")

    score = max(0.0, min(1.0, score))

    if score >= 0.65:
        tier = "strong"
    elif score >= 0.4:
        tier = "moderate"
    else:
        tier = "weak"

    return PasswordStrength(
        password=password,
        score=score,
        tier=tier,
        length=length,
        char_classes=char_classes,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_special=has_special,
        has_leet=has_leet,
        entropy_bits=entropy,
        weaknesses=weaknesses,
    )


def assess_strength_profile(passwords: list[str]) -> StrengthProfile:
    """Build an aggregate strength profile across all known passwords."""
    if not passwords:
        return StrengthProfile(
            tier="unknown", avg_score=0, avg_length=0, avg_char_classes=0,
            avg_entropy=0, min_length=0, max_length=0, reuse_ratio=0,
            leet_usage_pct=0, always_has_upper=False, always_has_lower=False,
            always_has_digit=False, always_has_special=False,
        )

    individual = [score_password_strength(pw) for pw in passwords]

    avg_score = sum(s.score for s in individual) / len(individual)
    avg_length = sum(s.length for s in individual) / len(individual)
    avg_classes = sum(s.char_classes for s in individual) / len(individual)
    avg_entropy = sum(s.entropy_bits for s in individual) / len(individual)
    lengths = [s.length for s in individual]
    leet_count = sum(1 for s in individual if s.has_leet)

    # Detect word reuse across passwords
    all_word_sets: list[set[str]] = []
    for pw in passwords:
        words = {w.lower() for w in deleet_to_words(pw) if len(w) >= 3}
        all_word_sets.append(words)

    reuse_count = 0
    for i, ws in enumerate(all_word_sets):
        for j in range(i + 1, len(all_word_sets)):
            if ws & all_word_sets[j]:
                reuse_count += 1
                break
    reuse_ratio = reuse_count / len(passwords) if passwords else 0.0

    # Aggregate weaknesses
    weakness_counts: Counter[str] = Counter()
    for s in individual:
        for w in s.weaknesses:
            weakness_counts[w] += 1
    common_weaknesses = [
        w for w, count in weakness_counts.most_common()
        if count >= len(individual) * 0.3
    ]

    if avg_score >= 0.65:
        tier = "strong"
    elif avg_score >= 0.4:
        tier = "moderate"
    else:
        tier = "weak"

    return StrengthProfile(
        tier=tier,
        avg_score=avg_score,
        avg_length=avg_length,
        avg_char_classes=avg_classes,
        avg_entropy=avg_entropy,
        min_length=min(lengths),
        max_length=max(lengths),
        reuse_ratio=reuse_ratio,
        leet_usage_pct=leet_count / len(individual),
        always_has_upper=all(s.has_upper for s in individual),
        always_has_lower=all(s.has_lower for s in individual),
        always_has_digit=all(s.has_digit for s in individual),
        always_has_special=all(s.has_special for s in individual),
        common_weaknesses=common_weaknesses,
        individual=individual,
    )
