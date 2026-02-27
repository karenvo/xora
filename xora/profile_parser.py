"""Parse free-text target profiles into structured data for password generation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_LEET_CHARS = set("013457@$!")

_VIN_RE = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")

_STOP_WORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "it", "was", "are", "be", "has",
    "had", "have", "not", "no", "yes", "this", "that", "she", "he", "her",
    "his", "they", "them", "its", "my", "our", "your", "who", "which",
    "what", "when", "where", "how", "all", "each", "every", "both",
    "few", "more", "most", "some", "any", "about", "up", "out", "if",
    "into", "than", "then", "also", "very", "just", "so", "can", "will",
    "should", "would", "could", "may", "might", "does", "did", "do",
    "been", "being", "were", "gets", "got", "get",
    "work", "laptop", "phone", "device", "deleted", "managed", "daily",
    "usually", "currently", "sometimes", "often", "always", "never",
    "prefers", "prefer", "since", "kept", "goes", "used", "using",
    "above", "below", "after", "before", "between", "under", "over",
    "none", "n/a", "fake", "unknown",
})

_ADDRESS_RE = re.compile(
    r"\b\d+\s+(N|S|E|W|NE|NW|SE|SW|North|South|East|West)?\s*\w+\s+"
    r"(St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl|Pkwy|Hwy)\b",
    re.IGNORECASE,
)
_ZIP_RE = re.compile(r"^\d{5}(-\d{4})?$")
_MEASUREMENT_RE = re.compile(
    r"^\~?\d+(\.\d+)?\s*(lbs?|kg|cm|ft|in|mm|mg|ml|oz|\"|\')$",
    re.IGNORECASE,
)
_MONEY_RE = re.compile(r"^\$[\d,.]+")
_PHONE_LIKE_RE = re.compile(r"^\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}")


@dataclass
class TargetProfile:
    """Structured representation of a target's personal information."""

    raw_text: str = ""
    name: str = ""
    first_name: str = ""
    last_name: str = ""
    nicknames: list[str] = field(default_factory=list)
    birthdate: str = ""
    partner_name: str = ""
    children_names: list[str] = field(default_factory=list)
    pet_names: list[str] = field(default_factory=list)
    interests: list[str] = field(default_factory=list)
    teams: list[str] = field(default_factory=list)
    companies: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    important_dates: list[str] = field(default_factory=list)
    known_passwords: list[str] = field(default_factory=list)
    extra_words: list[str] = field(default_factory=list)
    _curated_words: list[str] | None = field(default=None, repr=False)

    def set_curated_words(self, words: list[str]) -> None:
        """Set LLM-curated base words, bypassing the raw field concatenation."""
        self._curated_words = words

    def all_base_words(self) -> list[str]:
        """Return curated words if available, otherwise raw words with basic filtering."""
        if self._curated_words is not None:
            return self._curated_words

        words: list[str] = []
        for val in [self.first_name, self.last_name, self.partner_name]:
            if val:
                words.append(val)
        words.extend(self.nicknames)
        words.extend(self.children_names)
        words.extend(self.pet_names)
        words.extend(self.interests)
        words.extend(self.teams)
        words.extend(self.companies)
        words.extend(self.extra_words)
        return basic_word_filter([w for w in words if w])

    def all_numbers(self) -> list[str]:
        """Extract all numeric tokens from dates, phones, etc."""
        nums: list[str] = []
        for d in [self.birthdate] + self.important_dates:
            if not d:
                continue
            digits = re.findall(r"\d+", d)
            for dg in digits:
                nums.append(dg)
                if len(dg) == 4:
                    nums.append(dg[2:])
            parts = re.split(r"[/\-.]", d)
            if len(parts) >= 2:
                nums.append("".join(p.zfill(2) for p in parts[:2]))
        for ph in self.phone_numbers:
            clean = re.sub(r"\D", "", ph)
            if len(clean) >= 4:
                nums.append(clean[-4:])
            nums.append(clean)
        return list(dict.fromkeys(nums))

    def to_dict(self) -> dict:
        """Serialize to a dictionary."""
        d = {
            "name": self.name,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "nicknames": self.nicknames,
            "birthdate": self.birthdate,
            "partner_name": self.partner_name,
            "children_names": self.children_names,
            "pet_names": self.pet_names,
            "interests": self.interests,
            "teams": self.teams,
            "companies": self.companies,
            "emails": self.emails,
            "usernames": self.usernames,
            "phone_numbers": self.phone_numbers,
            "important_dates": self.important_dates,
            "known_passwords": self.known_passwords,
            "extra_words": self.extra_words,
        }
        if self._curated_words is not None:
            d["_curated_words"] = self._curated_words
        return d


def basic_word_filter(words: list[str], max_words: int = 60) -> list[str]:
    """Filter a raw word list down to password-plausible tokens.

    Used as a fallback when no LLM is available for curation.
    """
    cleaned: list[str] = []
    seen_lower: set[str] = set()

    for raw in words:
        w = re.sub(r"^[\-\*•]\s*", "", raw).strip()
        w = re.sub(r"\s*\(.*?\)\s*", " ", w).strip()
        if "—" in w:
            w = w.split("—")[0].strip()

        if not w:
            continue
        if _ADDRESS_RE.search(w):
            continue
        if _ZIP_RE.match(w):
            continue
        if _MEASUREMENT_RE.match(w):
            continue
        if _MONEY_RE.match(w):
            continue
        if _PHONE_LIKE_RE.match(w):
            continue
        if _VIN_RE.match(w):
            continue

        word_count = len(w.split())
        if word_count >= 5:
            continue
        if len(w) < 3 and not w.isdigit():
            continue
        if w.lower() in _STOP_WORDS:
            continue

        if word_count >= 3:
            alpha_words = [p for p in w.split() if p.isalpha()]
            stop_count = sum(1 for p in alpha_words if p.lower() in _STOP_WORDS)
            if stop_count > len(alpha_words) / 2:
                continue

        if any(ch in w for ch in ["~", "+", "ext.", "/"]):
            continue

        # Multi-word entries: produce both the space-collapsed form and
        # individual words, since "Forest Park" → "ForestPark" and "Forest", "Park"
        if " " in w:
            # CamelCase collapsed form (e.g., "Forest Park" → "ForestPark")
            collapsed = "".join(
                part.capitalize() for part in w.split() if part.isalpha()
            )
            if collapsed and len(collapsed) >= 3:
                ckey = collapsed.lower()
                if ckey not in seen_lower:
                    seen_lower.add(ckey)
                    cleaned.append(collapsed)
            # Individual meaningful words
            for part in w.split():
                if len(part) >= 3 and part.isalpha() and part.lower() not in _STOP_WORDS:
                    pkey = part.lower()
                    if pkey not in seen_lower:
                        seen_lower.add(pkey)
                        cleaned.append(part)
        else:
            key = w.lower()
            if key in seen_lower:
                continue
            seen_lower.add(key)
            cleaned.append(w)

    return cleaned[:max_words]


# =========================================================================
# Section header patterns (case-insensitive)
# =========================================================================

SECTION_PATTERNS: dict[str, list[str]] = {
    "passwords": [r"credential", r"known.*pass", r"login",
                  r"account\s*credential"],
    "personal": [r"personal", r"basic\s*info", r"about"],
    "relationships": [r"relationship", r"family", r"partner", r"spouse"],
    "pets": [r"pet", r"\bdog\b", r"\bcat\b", r"\banimal"],
    "interests": [r"interest", r"hobbi", r"favorite", r"likes"],
    "work": [r"work", r"job", r"company", r"employer", r"career"],
    "digital": [r"digital", r"online", r"email", r"username", r"\baccount\b",
                r"tech", r"device", r"social\s*media"],
    "dates": [r"date", r"anniversary", r"important"],
    "health": [r"\bhealth\b"],
    "extra": [r"extra", r"other", r"misc", r"additional", r"note",
              r"travel", r"vehicle", r"finance", r"physical", r"background",
              r"streaming", r"shopping", r"banking",
              r"primary\s*email", r"backup\s*email", r"work\s*portal"],
    "_skip": [r"fake\s*persona", r"testing\s*only", r"fictional",
              r"all\s*data.*fictional"],
}


def _match_section(line: str) -> str | None:
    """Determine which section a header line belongs to."""
    clean = re.sub(r"^[#=\-\s]+", "", line.strip())
    clean = re.sub(r"[=\-\s]+$", "", clean).strip().lower()
    if not clean:
        return None
    for section, patterns in SECTION_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, clean):
                return section
    return None


def _is_header_line(line: str) -> bool:
    """Check if a line looks like a section header."""
    stripped = line.strip()
    if stripped.startswith("#"):
        return True
    if re.match(r"^-{2,}\s*.+\s*-{2,}$", stripped):
        return True
    if re.match(r"^={2,}\s*.+\s*={2,}$", stripped):
        return True
    if re.match(r"^[=\-]{3,}$", stripped):
        return True
    if stripped.endswith(":") and len(stripped.split()) <= 4:
        return True
    return False


def _extract_value(line: str) -> str:
    """Strip key: value formatting, return the value part."""
    if ":" in line:
        return line.split(":", 1)[1].strip()
    return line.strip()


def _split_csv(text: str) -> list[str]:
    """Split comma or newline separated values."""
    items = re.split(r"[,\n]", text)
    return [i.strip() for i in items if i.strip()]


_DATE_RE = re.compile(
    r"\b(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}|\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})\b"
)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"\b\d[\d\s\-().]{6,}\d\b")


def _looks_like_password(line: str) -> bool:
    """Heuristic: does this line look like a password rather than prose?

    Checks for: no spaces, mixed character classes, leet speak,
    special characters embedded in words, typical password length.
    """
    s = line.strip()
    if not s or " " in s:
        return False
    if len(s) < 6 or len(s) > 40:
        return False
    if ":" in s and not any(c in s for c in "!@#$%^&*"):
        return False

    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_special = any(not c.isalnum() and c != "_" for c in s)
    has_underscore = "_" in s

    char_classes = sum([has_upper, has_lower, has_digit, has_special or has_underscore])

    if char_classes >= 3:
        return True

    leet_count = sum(1 for c in s if c in _LEET_CHARS)
    if leet_count >= 2 and has_lower:
        return True

    if has_underscore and (has_lower or has_upper) and len(s) >= 8:
        return True

    if has_upper and has_lower and has_digit and len(s) >= 8:
        return True

    return False


# =========================================================================
# Main parser
# =========================================================================

def parse_profile_text(raw_text: str) -> TargetProfile:
    """Parse a free-text profile into a TargetProfile.

    Supports both structured (section headers) and unstructured text.
    Uses a "credential zone" to keep sub-sections under ACCOUNT CREDENTIALS
    in the passwords bucket.
    """
    profile = TargetProfile(raw_text=raw_text)
    lines = raw_text.strip().splitlines()

    current_section: str | None = None
    in_credential_zone = False
    section_lines: dict[str, list[str]] = {}

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if re.match(r"^[=\-]{3,}$", stripped):
            continue

        if _is_header_line(stripped):
            sec = _match_section(stripped)
            if sec == "_skip":
                current_section = "_skip"
                in_credential_zone = False
                continue
            if sec == "passwords":
                in_credential_zone = True
                current_section = "passwords"
                section_lines.setdefault("passwords", [])
                continue
            if sec:
                if in_credential_zone:
                    current_section = "passwords"
                else:
                    current_section = sec
                section_lines.setdefault(current_section, [])
                continue

        title_sec = _match_section(stripped)
        if title_sec == "_skip":
            current_section = "_skip"
            in_credential_zone = False
            continue
        if title_sec == "passwords":
            in_credential_zone = True
            current_section = "passwords"
            section_lines.setdefault("passwords", [])
            continue

        if current_section == "_skip":
            continue

        if current_section:
            section_lines.setdefault(current_section, []).append(stripped)
        else:
            section_lines.setdefault("_unstructured", []).append(stripped)

    # Process structured sections
    for line in section_lines.get("personal", []):
        low = line.lower()
        val = _extract_value(line)
        if "name" in low and not profile.name:
            profile.name = val
            parts = val.split()
            if parts:
                profile.first_name = parts[0]
            if len(parts) > 1:
                profile.last_name = parts[-1]
        elif "birth" in low or "dob" in low or "born" in low:
            dates = _DATE_RE.findall(val)
            if dates:
                profile.birthdate = dates[0]
            else:
                profile.birthdate = val
        elif "nick" in low or "alias" in low or "goes by" in low:
            profile.nicknames.extend(_split_csv(val))

    for line in section_lines.get("relationships", []):
        low = line.lower()
        val = _extract_value(line)
        if any(w in low for w in ["partner", "spouse", "husband", "wife", "significant",
                                   "engaged", "boyfriend", "girlfriend", "fiancé"]):
            clean = re.sub(r"\s*\(.*?\)", "", val).strip()
            profile.partner_name = clean
        elif any(w in low for w in ["child", "son", "daughter", "kid"]):
            profile.children_names.extend(_split_csv(val))
        elif any(w in low for w in ["dog", "cat", "pet", "animal"]):
            if any(skip in low for skip in ["vet", "clinic", "hospital", "doctor"]):
                continue
            name_match = re.match(r"(\w+)", val)
            if name_match:
                profile.pet_names.append(name_match.group(1))

    for line in section_lines.get("pets", []):
        val = _extract_value(line)
        profile.pet_names.extend(_split_csv(val))

    for line in section_lines.get("interests", []):
        val = _extract_value(line)
        profile.interests.extend(_split_csv(val))

    for line in section_lines.get("work", []):
        val = _extract_value(line)
        profile.companies.extend(_split_csv(val))

    for line in section_lines.get("digital", []):
        low = line.lower()
        val = _extract_value(line)
        emails = _EMAIL_RE.findall(val)
        if emails:
            profile.emails.extend(emails)
        elif any(w in low for w in ["phone:", "laptop", "device", "smart",
                                     "streaming", "thermostat", "alexa",
                                     "social media"]):
            profile.extra_words.extend(_split_csv(val))
        elif _PHONE_RE.search(val):
            profile.phone_numbers.extend(_PHONE_RE.findall(val))
        elif any(w in low for w in ["username:", "handle:", "screen name:"]):
            profile.usernames.extend(_split_csv(val))
        else:
            profile.extra_words.extend(_split_csv(val))

    for line in section_lines.get("passwords", []):
        val = _extract_value(line)
        low = line.lower()
        if not val:
            continue
        emails = _EMAIL_RE.findall(val)
        if emails:
            profile.emails.extend(emails)
            continue
        if any(w in low for w in ["username", "user:"]):
            profile.usernames.append(val)
            continue
        if any(w in low for w in ["service", "service:"]):
            continue
        if _looks_like_password(val):
            profile.known_passwords.append(val)
        elif "password" in low or "pass:" in low or "pin:" in low:
            pw = val
            if ":" in line:
                pw = line.split(":", 1)[1].strip()
            if pw:
                profile.known_passwords.append(pw)

    for line in section_lines.get("dates", []):
        val = _extract_value(line)
        dates = _DATE_RE.findall(val)
        profile.important_dates.extend(dates if dates else [val])

    for line in section_lines.get("health", []):
        val = _extract_value(line)
        profile.extra_words.extend(_split_csv(val))

    for line in section_lines.get("extra", []):
        val = _extract_value(line)
        if _VIN_RE.match(val.split()[0] if val.split() else ""):
            continue
        profile.extra_words.extend(_split_csv(val))

    # Fallback: extract from unstructured text
    for line in section_lines.get("_unstructured", []):
        emails = _EMAIL_RE.findall(line)
        profile.emails.extend(emails)
        dates = _DATE_RE.findall(line)
        profile.important_dates.extend(dates)
        phones = _PHONE_RE.findall(line)
        profile.phone_numbers.extend(phones)

        if _looks_like_password(line.strip()):
            profile.known_passwords.append(line.strip())
            continue

        val = _extract_value(line)
        low = line.lower()
        if "name" in low and not profile.name:
            profile.name = val
            parts = val.split()
            if parts:
                profile.first_name = parts[0]
            if len(parts) > 1:
                profile.last_name = parts[-1]
        elif any(w in low for w in ["birth", "dob", "born"]):
            d = _DATE_RE.findall(val)
            if d:
                profile.birthdate = d[0]
        elif any(w in low for w in ["pet", "dog", "cat"]):
            profile.pet_names.extend(_split_csv(val))
        elif any(w in low for w in ["interest", "hobby", "hobbies", "likes", "favorite"]):
            profile.interests.extend(_split_csv(val))
        elif any(w in low for w in ["team", "sport"]):
            profile.teams.extend(_split_csv(val))
        elif any(w in low for w in ["partner", "spouse", "husband", "wife"]):
            profile.partner_name = val
        elif any(w in low for w in ["child", "son", "daughter", "kid"]):
            profile.children_names.extend(_split_csv(val))
        elif any(w in low for w in ["company", "work", "employer"]):
            profile.companies.extend(_split_csv(val))
        elif any(w in low for w in ["password", "pass"]):
            profile.known_passwords.append(val)
        else:
            words = [w for w in val.split() if len(w) >= 3 and w.isalpha()]
            profile.extra_words.extend(words)

    # Deduplicate all list fields
    for fld in [
        "nicknames", "children_names", "pet_names", "interests", "teams",
        "companies", "emails", "usernames", "phone_numbers",
        "important_dates", "known_passwords", "extra_words",
    ]:
        setattr(profile, fld, list(dict.fromkeys(getattr(profile, fld))))

    return profile


def parse_profile_file(path: str | Path) -> TargetProfile:
    """Read a file and parse it as a target profile."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_profile_text(text)


def profile_from_llm_data(llm_data: dict, raw_text: str) -> TargetProfile:
    """Build a TargetProfile directly from LLM-extracted data."""
    profile = TargetProfile(raw_text=raw_text)
    profile.name = llm_data.get("name", "")
    profile.first_name = llm_data.get("first_name", "")
    profile.last_name = llm_data.get("last_name", "")
    profile.nicknames = llm_data.get("nicknames", [])
    profile.birthdate = llm_data.get("birthdate", "")
    profile.partner_name = llm_data.get("partner_name", "")
    profile.children_names = llm_data.get("children_names", [])
    profile.pet_names = llm_data.get("pet_names", [])
    profile.interests = llm_data.get("interests", [])
    profile.teams = llm_data.get("teams", [])
    profile.companies = llm_data.get("companies", [])
    profile.emails = llm_data.get("emails", [])
    profile.usernames = llm_data.get("usernames", [])
    profile.phone_numbers = llm_data.get("phone_numbers", [])
    profile.important_dates = llm_data.get("important_dates", [])
    profile.known_passwords = llm_data.get("known_passwords", [])
    profile.extra_words = llm_data.get("extra_words", [])

    for fld in [
        "nicknames", "children_names", "pet_names", "interests", "teams",
        "companies", "emails", "usernames", "phone_numbers",
        "important_dates", "known_passwords", "extra_words",
    ]:
        setattr(profile, fld, list(dict.fromkeys(getattr(profile, fld))))

    return profile


def is_password_file(text: str, threshold: float = 0.6) -> bool:
    """Detect whether a file is primarily a list of passwords.

    Returns True if at least `threshold` of non-blank lines look like passwords
    and the file has no recognizable section headers.
    """
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines:
        return False
    for line in lines:
        if _is_header_line(line) and _match_section(line):
            return False
    pw_count = sum(1 for ln in lines if _looks_like_password(ln))
    return pw_count / len(lines) >= threshold


def _parse_password_file(text: str) -> TargetProfile:
    """Parse a file that is primarily a list of passwords.

    Every non-blank line is treated as a potential password. Lines that pass
    the heuristic go to known_passwords; the rest go to extra_words so
    they're still available for base-word extraction.
    """
    profile = TargetProfile(raw_text=text)
    for line in text.strip().splitlines():
        s = line.strip()
        if not s:
            continue
        if _looks_like_password(s):
            profile.known_passwords.append(s)
        else:
            profile.extra_words.append(s)
    profile.known_passwords = list(dict.fromkeys(profile.known_passwords))
    profile.extra_words = list(dict.fromkeys(profile.extra_words))
    return profile


def is_structured(text: str) -> bool:
    """Detect whether the profile text uses section headers (structured format).

    Returns True if the text has header lines (#, --- X ---, === X ===)
    that match known sections.
    """
    for line in text.strip().splitlines():
        if _is_header_line(line) and _match_section(line):
            return True
    return False
