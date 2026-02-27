"""Abstract base class for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Interface that all LLM providers must implement."""

    @abstractmethod
    def generate_text(self, prompt: str, temperature: float | None = None,
                      max_tokens: int | None = None) -> str:
        """Send a prompt and return the raw text response."""

    @abstractmethod
    def extract_json(self, text: str) -> str:
        """Extract a JSON fragment from raw LLM output."""

    @abstractmethod
    def parse_profile(self, raw_text: str) -> dict:
        """Use the LLM to extract structured profile data from free text."""

    @abstractmethod
    def suggest_passwords(
        self,
        profile_data: dict,
        patterns: list[dict],
        decoded_passwords: list[dict] | None = None,
        strength_profile: dict | None = None,
        word_tiers: dict | None = None,
        separator_fingerprint: dict | None = None,
        correlation_insights: list[dict] | None = None,
    ) -> list[str]:
        """Legacy single-shot password suggestion. Kept for backward compat."""

    @abstractmethod
    def analyze_patterns(self, passwords: list[str]) -> list[dict]:
        """Ask the LLM to describe patterns found in known passwords."""

    @abstractmethod
    def categorize_passwords(self, passwords: list[str], decoded_passwords: list[dict]) -> list[dict]:
        """Categorize decoded passwords by theme/context."""

    @abstractmethod
    def cross_reference(self, raw_text: str, llm_data: dict, parser_data: dict) -> dict:
        """Cross-reference LLM and parser extractions against the raw file."""

    @abstractmethod
    def infer_from_profile(self, profile_data: dict) -> list[dict]:
        """Reason about profile data to derive password-relevant words."""

    @abstractmethod
    def correlate_passwords_and_profile(
        self, decoded_passwords: list[dict], profile_data: dict, inferred: list[dict]
    ) -> list[dict]:
        """Cross-reference decoded passwords against profile data."""

    @abstractmethod
    def curate_base_words(self, profile_data: dict, known_passwords: list[str]) -> dict:
        """Select password-relevant words from the profile."""

    @abstractmethod
    def generate_custom_code(
        self,
        intelligence: dict,
    ) -> str:
        """Write custom generate_all() Python code for this specific target.

        The LLM receives an intelligence summary and writes a generate_all()
        function that is tailored to THIS person's password psychology. The
        function should include both hardcoded word/combo suggestions and
        combinatorial expansion logic.

        The returned code must define a function:
            def generate_all(policy: dict | None = None) -> list[tuple[float, str]]:

        The code can use these globals already defined in the skeleton:
            WORD_TIERS, NUMBERS, KNOWN_PASSWORDS, EMAILS, USERNAMES,
            CAP_STYLE, AVG_LENGTH, PATTERN_TEMPLATES, CATEGORY_WEIGHTS,
            PREFERRED_SEPARATORS, RARE_SEPARATORS, STRENGTH_TIER,
            STRENGTH_LEET_PCT, GLUE_WORDS, SEMANTIC_TEMPLATES,
            ROLE_VOCABULARY, LEET_MAP, DEFAULT_POLICY

        And these utility functions:
            _all_words(), case_variants(), leet_variants(),
            _weighted_seps(), number_suffixes(), passes_policy(),
            score_candidate()

        Returns:
            Python source code string defining generate_all() and any helpers.
        """


# ============================================================================
# PROMPT TEMPLATES
# ============================================================================

PROFILE_PARSE_PROMPT = """\
You are a red team assistant. Analyze the following free-text description of a \
target person. Extract ALL information that could be relevant to password generation.

Return ONLY valid JSON with these fields (use empty string or empty list if unknown):
{{
  "name": "",
  "first_name": "",
  "last_name": "",
  "nicknames": [],
  "birthdate": "",
  "partner_name": "",
  "children_names": [],
  "pet_names": [],
  "interests": [],
  "teams": [],
  "companies": [],
  "emails": [],
  "usernames": [],
  "phone_numbers": [],
  "important_dates": [],
  "known_passwords": [],
  "extra_words": []
}}

CRITICAL — known_passwords: If the text contains ANY passwords, credentials, \
passcodes, PINs, or login secrets, extract them EXACTLY as written into \
"known_passwords". Look for:
- Lines with "Password:", "Pass:", "PIN:" labels
- ANY field that contains a credential value
- Bare lines that look like passwords: no spaces, mixed case, digits mixed \
  with letters, leet speak (0 for o, @ for a, 3 for e, etc.), special characters \
  embedded in words, underscore-separated compounds
- If the entire file appears to be a list of passwords (no profile headers, \
  mostly single-word entries with mixed character classes), treat EVERY line \
  as a known password
These are the most important data points for password generation.

IMPORTANT — For "interests", "companies", and "extra_words": return SHORT \
tokens only (1-2 words each).

For "partner_name": return just the name, not relationship details.
For "pet_names": return just the pet's name, not breed/age/details.

Profile text:
{raw_text}
"""

PATTERN_ANALYZE_PROMPT = """\
You are a password pattern analyst. Examine these known passwords and describe \
the structural patterns, habits, and tendencies you observe.

Passwords:
{passwords}

Return ONLY valid JSON — an array of objects with:
{{
  "pattern": "description of the structural pattern",
  "template": "symbolic template like [CapWord][Year][Special]",
  "confidence": 0.0-1.0
}}
"""

PASSWORD_CATEGORIZE_PROMPT = """\
Categorize each password by its theme.

Passwords (original → decoded):
{passwords_list}

CATEGORIES: music, sports, gaming, tech, nature, places, family, food_drink, \
health, pop_culture, dates_numbers, unknown

Return ONLY a JSON object mapping each original password to its category:
{{"M0tl3yCr3w!":"music","BiscuitLuvr!23":"family",...}}
"""

CROSS_REFERENCE_PROMPT = """\
You are a red team data analyst performing a quality check. Two extraction \
methods have parsed the same raw profile file. Your job is to cross-reference \
both results against the ORIGINAL raw text and produce the best possible \
final extraction.

ORIGINAL RAW TEXT:
{raw_text}

EXTRACTION A (LLM initial parse):
{llm_json}

EXTRACTION B (Rule-based parser):
{parser_json}

YOUR TASK:
1. Read the original text carefully
2. For each field, pick the BETTER value from A or B — or merge them
3. If EITHER extraction missed something in the raw text, add it
4. If EITHER extraction contains garbage, remove it
5. known_passwords is the MOST CRITICAL field

Return ONLY valid JSON matching this schema:
{{
  "name": "",
  "first_name": "",
  "last_name": "",
  "nicknames": [],
  "birthdate": "",
  "partner_name": "",
  "children_names": [],
  "pet_names": [],
  "interests": [],
  "teams": [],
  "companies": [],
  "emails": [],
  "usernames": [],
  "phone_numbers": [],
  "important_dates": [],
  "known_passwords": [],
  "extra_words": []
}}
"""

PROFILE_INFERENCE_PROMPT = """\
You are a red team password psychologist. You have a target's structured profile \
data below. Your job is NOT to extract what's already there — that's done. \
Your job is to INFER password-relevant words that are NOT explicitly in the profile \
but can be DERIVED from it using YOUR knowledge of the world.

PROFILE DATA:
{profile_json}

REASONING CHAINS — work through EVERY applicable one:

1. EDUCATION — mascot, abbreviation, graduation year, school slang
2. CITIES & PLACES — airport codes, nicknames, local slang, sports teams
3. ETHNICITY & HERITAGE — common words in that language, cultural terms
4. MEDICAL & HEALTH — abbreviations, medication brand names, identity terms
5. VEHICLES — brand nicknames, model names, community terms
6. INTERESTS & HOBBIES — subculture terms, named objects, deep hobby jargon
7. WORK & CAREER — title abbreviations, industry jargon
8. FAMILY & RELATIONSHIPS — emotional anchors, wedding years, children birth years
9. EMOTIONAL MILESTONES — commemorative passwords
10. FINANCIAL & POSSESSIONS — bank abbreviations, car+year combos

OUTPUT FORMAT — Return ONLY valid JSON:
[
  {{
    "word": "Pisces",
    "rule": "zodiac",
    "source": "birthdate: March 14, 1988",
    "confidence": 0.7,
    "reasoning": "March 14 = Pisces; people use zodiac signs in passwords"
  }}
]

Generate 15-30 inferred words. No spaces in words — use CamelCase.
"""

CORRELATION_ANALYSIS_PROMPT = """\
You are a red team analyst performing deep correlation analysis. You have three \
data sources for the same target. Find NON-OBVIOUS connections.

DECODED PASSWORDS (original + decoded + extracted words):
{passwords_json}

PROFILE DATA:
{profile_json}

INFERRED WORDS (derived from profile):
{inferred_json}

LOOK FOR: shared years, life trajectory patterns, named object habits, \
separator fingerprints, category confirmations, emotional year reuse, \
cross-field combinations.

Return ONLY valid JSON — an array of correlation insights:
[
  {{
    "pattern_name": "shared_year",
    "evidence": ["..."],
    "insight": "...",
    "confidence": 0.85,
    "suggested_words": ["..."]
  }}
]

Be specific. Cite actual passwords and profile data. Generate 5-15 insights.
"""

BASE_WORDS_CURATE_PROMPT = """\
You are a red team password analyst. Select words that a target would ACTUALLY \
use in their passwords.

STEP 1 — Study the known passwords:
{known_passwords}

STEP 2 — Select password-relevant words from the profile:
{profile_json}

RULES:
- Single words or tight 2-word compounds (CamelCase)
- Include: names, pets, cities, bands, hobby keywords, meaningful nouns
- EXCLUDE: sentences, addresses, phone numbers, generic words
- Aim for 15-30 high-signal words

Return ONLY valid JSON:
{{
  "base_words": ["word1", "word2", ...],
  "reasoning": "Brief explanation"
}}
"""

# Legacy prompt — kept for backward compatibility
PASSWORD_SUGGEST_PROMPT = """\
You are a red team password psychologist. Generate password guesses that \
this SPECIFIC person would actually create.

═══ KNOWN PASSWORDS (decoded) ═══
{decoded_passwords_json}

═══ STRUCTURAL TEMPLATES ═══
{patterns_json}

═══ WORD POOL ═══
{word_tiers_json}

═══ SEPARATOR FINGERPRINT ═══
{separator_json}

═══ STRENGTH PROFILE ═══
{strength_json}

═══ CORRELATIONS ═══
{correlation_json}

Generate {count} password candidates. NO spaces. Use words from the pool.
Follow the separator fingerprint and match the strength profile.

Return ONLY a JSON array of strings:
["password1", "CompoundWord", "l33tV3rsion", ...]
"""

# ============================================================================
# CODE GENERATION PROMPT
# ============================================================================

CODE_GENERATION_PROMPT = """\
You are an expert Python developer and red team password psychologist. Your job \
is to write a custom `generate_all()` function tailored to ONE specific person's \
password psychology.

═══ TARGET INTELLIGENCE ═══
{intelligence_json}

═══ YOUR TASK ═══

Write a Python function `generate_all(policy=None)` that generates password \
candidates specifically for THIS person. The function must:

1. Return `list[tuple[float, str]]` — list of (score, password) pairs
2. Call `passes_policy(pw, pol)` to filter passwords
3. Call `score_candidate(pw)` to score each password
4. Use `seen: set[str]` to deduplicate

Available globals (already defined — do NOT redefine):
- Data: WORD_TIERS, NUMBERS, KNOWN_PASSWORDS, EMAILS, USERNAMES
- Data: CAP_STYLE, AVG_LENGTH, PATTERN_TEMPLATES, CATEGORY_WEIGHTS
- Data: PREFERRED_SEPARATORS, RARE_SEPARATORS, STRENGTH_TIER, STRENGTH_LEET_PCT
- Data: GLUE_WORDS, SEMANTIC_TEMPLATES, ROLE_VOCABULARY, LEET_MAP, DEFAULT_POLICY
- Funcs: _all_words(), case_variants(word), leet_variants(word, max_variants)
- Funcs: _weighted_seps(seps, total), number_suffixes()
- Funcs: passes_policy(pw, policy), score_candidate(pw)

STRATEGY — Based on this person's psychology:
- Strength tier is "{strength_tier}" — {strength_guidance}
- Leet usage is {leet_pct:.0%} — {leet_guidance}
- Their preferred separators are {preferred_seps} — weight these heavily
- Their average password length is {avg_length} — target this range
- Their top categories are: {top_categories}
- Cap style is "{cap_style}" — bias case_variants accordingly

YOUR CODE MUST DO TWO THINGS:

PART 1 — SUGGEST ADDITIONAL WORDS & COMBOS:
Based on the target's profile, category weights, and password psychology, define \
a hardcoded list of 50-150 additional password candidates inside the function. \
These should be psychologically-targeted guesses: compound words, themed combos, \
leet-encoded phrases, and identity-anchored passwords this person would actually \
type. Think about:
- Template-filling: combine pool words using their semantic templates
- Novel combinations: words from different tiers that share psychological meaning
- Style-matched variants: apply their leet/case/separator habits
- Context passwords: what they'd use for bank, social media, gaming, work accounts

PART 2 — COMBINATORIAL GENERATION ENGINE:
Write the expansion logic that uses the global word pool, numbers, separators, \
leet map, and glue words to generate candidates. Theme-specific strategy:
{theme_specific_instructions}

Generate 50,000-200,000 candidates total (quality over quantity).

IMPORTANT CONSTRAINTS:
- Output ONLY the Python code — no markdown, no explanation
- The code must be valid Python that runs standalone
- Define `generate_all()` and any helper functions it needs
- Do NOT redefine globals or utility functions (they're already available)
- Use f-strings with double braces {{}} for literal braces in strings
- The `_add` helper pattern is recommended for dedup + policy + scoring
- Do NOT use `import` statements — itertools, re, sys are already imported
"""
