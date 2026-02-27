"""Semantic decomposition of passwords.

Goes beyond structural templates ({word_cap}{special}{year4}) to understand
the MEANING behind each component:

    4CDCr0cks1980 → (band_name: ACDC)(glue: Rocks)(year: 1980)
    Jump!V@nH@len_1984 → (song: Jump)(sep: !)(artist: VanHalen)(sep: _)(year: 1984)
    BiscuitLuvr!23 → (pet_name: Biscuit)(glue: Luvr)(sep: !)(year_short: 23)

This enables the generator to recombine semantic roles with different values:
    (band_name: Whitesnake)(glue: Rocks)(year: 1987)
    (song: Welcome)(sep: !)(artist: GnR)(sep: _)(year: 1987)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from xora.password_profiler import deleet, deleet_to_words

log = logging.getLogger(__name__)


# =========================================================================
# DATA STRUCTURES
# =========================================================================

@dataclass
class SemanticComponent:
    """A single meaningful piece of a password."""
    value: str
    role: str       # band_name, song, artist, pet_name, place, glue, sep, year, number, etc.
    source: str     # which profile field or password context it came from
    original: str   # the original (possibly leet-encoded) form

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "role": self.role,
            "source": self.source,
            "original": self.original,
        }


@dataclass
class SemanticPassword:
    """A password decomposed into semantic components."""
    original: str
    decoded: str
    components: list[SemanticComponent]
    semantic_template: str  # e.g. "(band_name)(glue)(year)"
    category: str           # overall theme: music, family, places, etc.

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "decoded": self.decoded,
            "components": [c.to_dict() for c in self.components],
            "semantic_template": self.semantic_template,
            "category": self.category,
        }


@dataclass
class SemanticAnalysis:
    """Aggregated semantic analysis across all known passwords."""
    passwords: list[SemanticPassword] = field(default_factory=list)
    glue_words: list[str] = field(default_factory=list)
    semantic_templates: list[str] = field(default_factory=list)
    role_vocabulary: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "passwords": [p.to_dict() for p in self.passwords],
            "glue_words": self.glue_words,
            "semantic_templates": self.semantic_templates,
            "role_vocabulary": self.role_vocabulary,
        }


# =========================================================================
# COMMON GLUE WORDS — words people insert between meaningful components
# =========================================================================

_KNOWN_GLUE_WORDS: set[str] = {
    "rocks", "rock", "rules", "4ever", "forever", "lover", "luvr", "luv",
    "love", "life", "is", "the", "my", "and", "band", "fan", "crew",
    "girl", "boy", "man", "baby", "queen", "king", "hero", "warrior",
    "junkie", "freak", "head", "master", "boss", "pro", "god", "lord",
    "world", "nation", "live", "roll", "n", "of", "in", "on", "to",
    "me", "it", "up", "go", "can", "you", "if", "catch", "welcome",
    "pour", "some", "sugar", "breakin", "round", "here", "again",
    "back", "jump", "guitar", "slash",
}


# =========================================================================
# RULE-BASED SEMANTIC DECOMPOSITION
# =========================================================================

def _classify_word_role(
    word: str,
    profile_data: dict,
    all_decoded_words: set[str],
) -> tuple[str, str]:
    """Classify a decoded word into a semantic role.

    Returns (role, source) where role is like 'pet_name', 'band_name', etc.
    and source describes where it was matched.
    """
    low = word.lower()

    # Check against profile fields
    for pet in profile_data.get("pet_names", []):
        if low == pet.lower() or low in pet.lower().split():
            return "pet_name", f"pet_names: {pet}"

    if profile_data.get("partner_name"):
        for part in profile_data["partner_name"].split():
            if low == part.lower():
                return "partner_name", f"partner_name: {profile_data['partner_name']}"

    for child in profile_data.get("children_names", []):
        if low == child.lower() or low in child.lower().split():
            return "child_name", f"children_names: {child}"

    for nick in profile_data.get("nicknames", []):
        if low == nick.lower():
            return "nickname", f"nicknames: {nick}"

    if profile_data.get("first_name") and low == profile_data["first_name"].lower():
        return "own_name", f"first_name: {profile_data['first_name']}"
    if profile_data.get("last_name") and low == profile_data["last_name"].lower():
        return "own_name", f"last_name: {profile_data['last_name']}"

    for interest in profile_data.get("interests", []):
        for iw in interest.lower().split():
            if low == iw and len(low) >= 3:
                return "interest", f"interests: {interest}"

    for company in profile_data.get("companies", []):
        for cw in company.lower().split():
            if low == cw and len(low) >= 3:
                return "work", f"companies: {company}"

    for team in profile_data.get("teams", []):
        for tw in team.lower().split():
            if low == tw and len(low) >= 3:
                return "team", f"teams: {team}"

    for extra in profile_data.get("extra_words", []):
        if low == extra.lower():
            return "profile_word", f"extra_words: {extra}"

    if low in _KNOWN_GLUE_WORDS:
        return "glue", "common glue word"

    # If the word appears in multiple passwords but isn't in the profile,
    # it's likely a thematic word (band name, song, etc.)
    return "theme_word", "from password context"


def _segment_decoded(password: str, decoded: str, words: list[str]) -> list[dict]:
    """Segment a decoded password into chunks with positional info."""
    chunks: list[dict] = []
    remaining = decoded
    pos = 0

    for word in words:
        idx = remaining.lower().find(word.lower())
        if idx == -1:
            continue

        # Anything before the word is separator/glue
        if idx > 0:
            prefix = remaining[:idx]
            for c in prefix:
                if not c.isalnum():
                    chunks.append({"value": c, "type": "separator"})
                elif c.isdigit():
                    chunks.append({"value": c, "type": "digit"})

        chunks.append({"value": word, "type": "word"})
        remaining = remaining[idx + len(word):]
        pos = idx + len(word)

    # Trailing content (numbers, separators)
    for c in remaining:
        if c.isdigit():
            # Accumulate digits
            if chunks and chunks[-1]["type"] == "digit":
                chunks[-1]["value"] += c
            else:
                chunks.append({"value": c, "type": "digit"})
        elif not c.isalnum():
            chunks.append({"value": c, "type": "separator"})
        elif c.isalpha():
            if chunks and chunks[-1]["type"] == "word":
                chunks[-1]["value"] += c
            else:
                chunks.append({"value": c, "type": "word"})

    return chunks


def decompose_password_rule_based(
    original: str,
    decoded: str,
    words: list[str],
    profile_data: dict,
    all_decoded_words: set[str],
) -> SemanticPassword:
    """Decompose a single password into semantic components using rules."""
    components: list[SemanticComponent] = []
    chunks = _segment_decoded(original, decoded, words)

    for chunk in chunks:
        if chunk["type"] == "separator":
            components.append(SemanticComponent(
                value=chunk["value"],
                role="separator",
                source="structural",
                original=chunk["value"],
            ))
        elif chunk["type"] == "digit":
            val = chunk["value"]
            if len(val) == 4 and val.isdigit():
                try:
                    y = int(val)
                    if 1940 <= y <= 2030:
                        components.append(SemanticComponent(
                            value=val, role="year", source="year pattern",
                            original=val,
                        ))
                        continue
                except ValueError:
                    pass
            components.append(SemanticComponent(
                value=val, role="number", source="numeric",
                original=val,
            ))
        elif chunk["type"] == "word":
            role, source = _classify_word_role(
                chunk["value"], profile_data, all_decoded_words
            )
            components.append(SemanticComponent(
                value=chunk["value"],
                role=role,
                source=source,
                original=chunk["value"],
            ))

    template = "(" + ")(".join(c.role for c in components) + ")"
    category = _infer_category(components)

    return SemanticPassword(
        original=original,
        decoded=decoded,
        components=components,
        semantic_template=template,
        category=category,
    )


def _infer_category(components: list[SemanticComponent]) -> str:
    """Infer the overall category from the semantic roles present."""
    roles = {c.role for c in components}
    if "pet_name" in roles:
        return "family"
    if "partner_name" in roles or "child_name" in roles:
        return "family"
    if roles & {"band_name", "song", "artist"}:
        return "music"
    if "team" in roles:
        return "sports"
    if "interest" in roles:
        return "interests"
    if "work" in roles:
        return "work"
    if roles == {"theme_word"} or roles == {"theme_word", "glue"}:
        return "theme"
    return "mixed"


# =========================================================================
# FULL ANALYSIS
# =========================================================================

def analyze_semantics_rule_based(
    decoded_passwords: list[dict],
    profile_data: dict,
) -> SemanticAnalysis:
    """Analyze all passwords semantically using rule-based classification."""
    all_decoded_words: set[str] = set()
    for entry in decoded_passwords:
        for w in entry.get("words", []):
            all_decoded_words.add(w.lower())

    analysis = SemanticAnalysis()
    glue_counter: dict[str, int] = {}
    role_vocab: dict[str, set[str]] = {}

    for entry in decoded_passwords:
        sp = decompose_password_rule_based(
            original=entry["original"],
            decoded=entry["decoded"],
            words=entry.get("words", []),
            profile_data=profile_data,
            all_decoded_words=all_decoded_words,
        )
        analysis.passwords.append(sp)

        # Collect glue words
        for comp in sp.components:
            if comp.role == "glue":
                glue_counter[comp.value] = glue_counter.get(comp.value, 0) + 1

            # Build role vocabulary
            if comp.role not in ("separator", "number", "year"):
                if comp.role not in role_vocab:
                    role_vocab[comp.role] = set()
                role_vocab[comp.role].add(comp.value)

    # Sort glue words by frequency
    analysis.glue_words = sorted(
        glue_counter.keys(),
        key=lambda w: glue_counter[w],
        reverse=True,
    )

    # Collect unique semantic templates
    templates: list[str] = []
    for sp in analysis.passwords:
        if sp.semantic_template not in templates:
            templates.append(sp.semantic_template)
    analysis.semantic_templates = templates

    # Convert sets to sorted lists
    analysis.role_vocabulary = {
        role: sorted(words)
        for role, words in role_vocab.items()
    }

    return analysis


# =========================================================================
# LLM-BASED SEMANTIC DECOMPOSITION
# =========================================================================

SEMANTIC_DECOMPOSITION_PROMPT = """\
You are a red team password psychologist performing SEMANTIC DECOMPOSITION. \
For each password below, break it into meaningful components and assign a \
SEMANTIC ROLE to each piece.

DECODED PASSWORDS (original + decoded form + extracted words):
{passwords_json}

PROFILE DATA (for matching components to the target's life):
{profile_json}

FOR EACH PASSWORD, decompose it like this:

Example: "4CDCr0cks1980" decoded as "ACDCRocks1980"
→ components: [
    {{"value": "ACDC", "role": "band_name", "source": "music interest"}},
    {{"value": "Rocks", "role": "glue", "source": "common glue word — enthusiasm"}},
    {{"value": "1980", "role": "year", "source": "album/band era year"}}
  ]
  semantic_template: "(band_name)(glue)(year)"
  category: "music"

Example: "Jump!V@nH@len_1984" decoded as "Jump!VanHalen_1984"
→ components: [
    {{"value": "Jump", "role": "song", "source": "Van Halen song title"}},
    {{"value": "!", "role": "separator", "source": "structural"}},
    {{"value": "VanHalen", "role": "artist", "source": "band/artist name"}},
    {{"value": "_", "role": "separator", "source": "structural"}},
    {{"value": "1984", "role": "year", "source": "album name AND year"}}
  ]
  semantic_template: "(song)(separator)(artist)(separator)(year)"
  category: "music"

Example: "BiscuitLuvr!23" decoded as "BiscuitLuvr!23"
→ components: [
    {{"value": "Biscuit", "role": "pet_name", "source": "pet_names: Biscuit"}},
    {{"value": "Luvr", "role": "glue", "source": "affection glue word"}},
    {{"value": "!", "role": "separator", "source": "structural"}},
    {{"value": "23", "role": "number", "source": "short year or lucky number"}}
  ]
  semantic_template: "(pet_name)(glue)(separator)(number)"
  category: "family"

SEMANTIC ROLES (use these consistently):
- band_name: A music band/group name
- artist: A solo artist or performer name
- song: A song title or lyric fragment
- album: An album name
- pet_name: A pet's name (matched to profile)
- partner_name: Partner/spouse name
- child_name: Child's name
- own_name: Target's own first/last name
- nickname: Target's nickname
- place: City, country, location
- interest: Hobby or interest keyword
- work: Job/employer related
- team: Sports team
- glue: A connecting/filler word (Rocks, Love, 4ever, Band, Fan, Life, Rules, etc.)
- separator: Special character used as delimiter (!, _, #, $, @, &)
- year: 4-digit year with contextual significance
- number: Other numeric component
- theme_word: A thematic word related to the password's context but not in profile
- phrase: A common phrase or saying fragment ("WelcomeToTheJungle", "CatchMeIfYouCan")

IMPORTANT — GLUE WORDS:
Glue words are the connective tissue between meaningful components. They reveal \
how the target THINKS about combining things. Common glue patterns:
- Enthusiasm: "Rocks", "Rules", "4ever", "Forever"
- Affection: "Love", "Luvr", "Luv", "Baby", "Fan"
- Identity: "Life", "Girl", "Boy", "Man", "Queen", "King"
- Action: "Jump", "Roll", "Live", "Go", "Rock"
- Status: "Hero", "Master", "Boss", "Pro", "God"
Track these carefully — they'll be reused with different content words.

Return ONLY valid JSON — an array with one entry per password:
[
  {{
    "original": "the original password",
    "decoded": "the decoded form",
    "components": [
      {{"value": "...", "role": "...", "source": "brief explanation"}}
    ],
    "semantic_template": "(role1)(role2)(role3)",
    "category": "music|family|places|tech|interests|mixed|etc."
  }},
  ...
]
"""


def analyze_semantics_llm(
    decoded_passwords: list[dict],
    profile_data: dict,
    provider: object,
) -> SemanticAnalysis:
    """Analyze passwords semantically using an LLM."""
    from xora.llm.base import LLMProvider
    assert isinstance(provider, LLMProvider)

    prompt = SEMANTIC_DECOMPOSITION_PROMPT.format(
        passwords_json=json.dumps(decoded_passwords, indent=2),
        profile_json=json.dumps(profile_data, indent=2),
    )

    try:
        response = provider.generate_text(prompt, max_tokens=8192)
        raw = provider.extract_json(response)
        try:
            results = json.loads(raw)
        except json.JSONDecodeError:
            # Attempt to salvage a truncated JSON array
            if raw.lstrip().startswith("["):
                last_brace = raw.rfind("}")
                if last_brace > 0:
                    truncated = raw[:last_brace + 1].rstrip().rstrip(",") + "]"
                    results = json.loads(truncated)
                    log.warning(
                        "LLM semantic decomposition truncated — salvaged %d entries",
                        len(results) if isinstance(results, list) else 0,
                    )
                else:
                    raise
            else:
                raise
    except Exception as exc:
        log.warning("LLM semantic decomposition failed: %s", exc)
        return analyze_semantics_rule_based(decoded_passwords, profile_data)

    if not isinstance(results, list):
        return analyze_semantics_rule_based(decoded_passwords, profile_data)

    analysis = SemanticAnalysis()
    glue_counter: dict[str, int] = {}
    role_vocab: dict[str, set[str]] = {}

    for item in results:
        if not isinstance(item, dict):
            continue

        components = []
        for comp_data in item.get("components", []):
            comp = SemanticComponent(
                value=comp_data.get("value", ""),
                role=comp_data.get("role", "unknown"),
                source=comp_data.get("source", ""),
                original=comp_data.get("value", ""),
            )
            components.append(comp)

            if comp.role == "glue":
                glue_counter[comp.value] = glue_counter.get(comp.value, 0) + 1
            if comp.role not in ("separator", "number", "year"):
                if comp.role not in role_vocab:
                    role_vocab[comp.role] = set()
                role_vocab[comp.role].add(comp.value)

        sp = SemanticPassword(
            original=item.get("original", ""),
            decoded=item.get("decoded", ""),
            components=components,
            semantic_template=item.get("semantic_template", ""),
            category=item.get("category", "unknown"),
        )
        analysis.passwords.append(sp)

    analysis.glue_words = sorted(
        glue_counter.keys(),
        key=lambda w: glue_counter[w],
        reverse=True,
    )
    templates: list[str] = []
    for sp in analysis.passwords:
        if sp.semantic_template and sp.semantic_template not in templates:
            templates.append(sp.semantic_template)
    analysis.semantic_templates = templates
    analysis.role_vocabulary = {
        role: sorted(words)
        for role, words in role_vocab.items()
    }

    return analysis
