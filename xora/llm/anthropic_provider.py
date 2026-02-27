"""Anthropic (Claude) provider."""

from __future__ import annotations

import json
import logging
import os

import httpx

from xora.llm.base import (
    BASE_WORDS_CURATE_PROMPT,
    CODE_GENERATION_PROMPT,
    CORRELATION_ANALYSIS_PROMPT,
    CROSS_REFERENCE_PROMPT,
    LLMProvider,
    PASSWORD_CATEGORIZE_PROMPT,
    PASSWORD_SUGGEST_PROMPT,
    PATTERN_ANALYZE_PROMPT,
    PROFILE_INFERENCE_PROMPT,
    PROFILE_PARSE_PROMPT,
)

log = logging.getLogger(__name__)

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"


class AnthropicProvider(LLMProvider):
    """Connect to the Anthropic (Claude) API."""

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        api_key: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        timeout: float = 120,
    ):
        self.model = model
        self.api_key = api_key or os.environ.get("XORA_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY env var "
                "or pass --api-key."
            )
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._client = httpx.Client(
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            timeout=self.timeout,
        )

    def generate_text(self, prompt: str, temperature: float | None = None,
                      max_tokens: int | None = None) -> str:
        return self._message(prompt, temperature, max_tokens=max_tokens)

    def extract_json(self, text: str) -> str:
        return self._extract_json(text)

    _JSON_SYSTEM = (
        "You are a data extraction assistant. Always respond with valid JSON "
        "only — no markdown fences, no commentary, no explanation."
    )

    def _message(self, prompt: str, temperature: float | None = None,
                 max_tokens: int | None = None,
                 system: str | None = None) -> str:
        """Send a message to the Anthropic API and return the response text."""
        payload = {
            "model": self.model,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature if temperature is not None else self.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system
        log.debug("Anthropic request model=%s", self.model)
        resp = self._client.post(ANTHROPIC_API_URL, json=payload)
        if resp.status_code != 200:
            try:
                body = resp.json()
                err_type = body.get("error", {}).get("type", "unknown")
                err_msg = body.get("error", {}).get("message", resp.text)
            except Exception:
                err_type = "unknown"
                err_msg = resp.text
            raise RuntimeError(
                f"Anthropic API error ({err_type}): {err_msg}"
            )
        data = resp.json()
        return data["content"][0]["text"]

    def _extract_json(self, text: str) -> str:
        """Try to extract JSON from an LLM response."""
        text = text.strip()
        if "```" in text:
            parts = text.split("```")
            for part in parts:
                cleaned = part.strip()
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:].strip()
                if cleaned.startswith(("{", "[")):
                    return cleaned
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = text.find(start_char)
            end = text.rfind(end_char)
            if start != -1 and end != -1 and end > start:
                return text[start : end + 1]
        return text

    def _extract_code(self, text: str) -> str:
        """Extract Python code from an LLM response."""
        text = text.strip()
        if "```" in text:
            parts = text.split("```")
            for part in parts:
                cleaned = part.strip()
                if cleaned.startswith("python"):
                    cleaned = cleaned[6:].strip()
                elif cleaned.startswith("py"):
                    cleaned = cleaned[2:].strip()
                if "def " in cleaned:
                    return cleaned
        if "def generate_all" in text:
            start = text.find("def ")
            return text[start:]
        return text

    def _parse_json_list(self, response: str, label: str = "result") -> list[str]:
        """Parse a JSON array of strings, recovering from truncation."""
        raw = self._extract_json(response)
        try:
            result = json.loads(raw)
            if isinstance(result, list):
                return [str(p) for p in result if isinstance(p, str) and " " not in str(p)]
            return []
        except json.JSONDecodeError:
            if raw.lstrip().startswith("["):
                last_quote = raw.rfind('"')
                if last_quote > 0:
                    truncated = raw[:last_quote + 1].rstrip().rstrip(",") + "]"
                    try:
                        result = json.loads(truncated)
                        if isinstance(result, list):
                            salvaged = [str(p) for p in result if isinstance(p, str) and " " not in str(p)]
                            log.warning(
                                "Anthropic %s response was truncated — salvaged %d entries",
                                label, len(salvaged),
                            )
                            return salvaged
                    except json.JSONDecodeError:
                        pass
            log.warning("Failed to parse Anthropic %s as JSON", label)
            return []

    # ------------------------------------------------------------------
    # LLM method implementations
    # ------------------------------------------------------------------

    def parse_profile(self, raw_text: str) -> dict:
        prompt = PROFILE_PARSE_PROMPT.format(raw_text=raw_text)
        response = self._message(prompt, system=self._JSON_SYSTEM)
        try:
            return json.loads(self._extract_json(response))
        except json.JSONDecodeError:
            log.warning("Failed to parse Anthropic profile response as JSON")
            return {}

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
        prompt = PASSWORD_SUGGEST_PROMPT.format(
            count=80,
            decoded_passwords_json=json.dumps(decoded_passwords or [], indent=2),
            patterns_json=json.dumps(patterns, indent=2),
            word_tiers_json=json.dumps(word_tiers or {}, indent=2),
            separator_json=json.dumps(
                separator_fingerprint or {"preferred": [], "rare": []}, indent=2
            ),
            strength_json=json.dumps(strength_profile or {}, indent=2),
            correlation_json=json.dumps(correlation_insights or [], indent=2),
        )
        return self._parse_json_list(
            self._message(prompt, system=self._JSON_SYSTEM), "password suggestions"
        )

    def analyze_patterns(self, passwords: list[str]) -> list[dict]:
        prompt = PATTERN_ANALYZE_PROMPT.format(passwords="\n".join(passwords))
        response = self._message(prompt, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            log.warning("Failed to parse Anthropic pattern analysis as JSON")
            return []

    def categorize_passwords(self, passwords: list[str], decoded_passwords: list[dict]) -> list[dict]:
        lines = "\n".join(
            f"  {d['original']} → {d['decoded']}" for d in decoded_passwords
        )
        prompt = PASSWORD_CATEGORIZE_PROMPT.format(passwords_list=lines)
        response = self._message(prompt, max_tokens=4096, system=self._JSON_SYSTEM)
        raw = self._extract_json(response)
        try:
            mapping = json.loads(raw)
            if not isinstance(mapping, dict):
                raise ValueError("expected dict")
            return [
                {"original": d["original"], "category": mapping.get(d["original"], "unknown"),
                 "confidence": 0.8}
                for d in decoded_passwords
            ]
        except Exception:
            log.warning("Failed to parse Anthropic password categorization as JSON")
            return []

    def cross_reference(self, raw_text: str, llm_data: dict, parser_data: dict) -> dict:
        prompt = CROSS_REFERENCE_PROMPT.format(
            raw_text=raw_text,
            llm_json=json.dumps(llm_data, indent=2),
            parser_json=json.dumps(parser_data, indent=2),
        )
        response = self._message(prompt, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            return result if isinstance(result, dict) else {}
        except json.JSONDecodeError:
            log.warning("Failed to parse Anthropic cross-reference response as JSON")
            return {}

    def infer_from_profile(self, profile_data: dict) -> list[dict]:
        prompt = PROFILE_INFERENCE_PROMPT.format(
            profile_json=json.dumps(profile_data, indent=2),
        )
        response = self._message(prompt, max_tokens=8192, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            log.warning("Failed to parse Anthropic inference response as JSON")
            return []

    def correlate_passwords_and_profile(
        self, decoded_passwords: list[dict], profile_data: dict, inferred: list[dict]
    ) -> list[dict]:
        prompt = CORRELATION_ANALYSIS_PROMPT.format(
            passwords_json=json.dumps(decoded_passwords, indent=2),
            profile_json=json.dumps(profile_data, indent=2),
            inferred_json=json.dumps(inferred, indent=2),
        )
        response = self._message(prompt, max_tokens=8192, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            log.warning("Failed to parse Anthropic correlation response as JSON")
            return []

    def curate_base_words(self, profile_data: dict, known_passwords: list[str]) -> dict:
        prompt = BASE_WORDS_CURATE_PROMPT.format(
            known_passwords="\n".join(known_passwords) if known_passwords else "(none available)",
            profile_json=json.dumps(profile_data, indent=2),
        )
        response = self._message(prompt, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            if isinstance(result, dict) and "base_words" in result:
                return result
            if isinstance(result, list):
                return {"base_words": [str(w) for w in result], "reasoning": ""}
            return {"base_words": [], "reasoning": ""}
        except json.JSONDecodeError:
            log.warning("Failed to parse Anthropic base words curation as JSON")
            return {"base_words": [], "reasoning": ""}

    # ------------------------------------------------------------------
    # Code generation
    # ------------------------------------------------------------------

    def generate_custom_code(
        self,
        intelligence: dict,
    ) -> str:
        """Write custom generate_all() code tailored to this target."""
        strength = intelligence.get("strength_tier", "unknown")
        leet_pct = intelligence.get("leet_usage_pct", 0.0)
        avg_length = intelligence.get("avg_length", 12)
        pref_seps = intelligence.get("preferred_separators", [])
        cap_style = intelligence.get("cap_style", "mixed")
        cat_weights = intelligence.get("category_weights", {})
        word_tiers = intelligence.get("word_tiers", {})

        top_cats = sorted(
            cat_weights.items(), key=lambda x: x[1], reverse=True
        )[:5] if cat_weights else []
        top_categories = ", ".join(f"{c[0]} ({c[1]:.0%})" for c in top_cats) or "unknown"

        if strength == "weak":
            strength_guidance = "generate simple passwords: single words + short numbers"
        elif strength == "strong":
            strength_guidance = "generate complex passwords: multi-word compounds, deep leet"
        else:
            strength_guidance = "generate balanced passwords: word + separator + number combos"

        if leet_pct >= 0.5:
            leet_guidance = "apply aggressive leet to most candidates using LEET_MAP"
        elif leet_pct >= 0.2:
            leet_guidance = "apply selective leet to about half the candidates"
        else:
            leet_guidance = "minimal or no leet — keep most passwords clean"

        theme_lines = []
        for cat_name, _ in top_cats:
            theme_lines.append(
                f"   - {cat_name.upper()}: combine relevant {cat_name} words from the pool"
            )
        if not theme_lines:
            theme_lines.append("   - Combine critical and high-tier words with numbers and separators")

        compact_intel = {
            "word_tier_counts": {k: len(v) for k, v in word_tiers.items()},
            "word_tier_samples": {k: v[:8] for k, v in word_tiers.items()},
            "known_passwords": intelligence.get("known_passwords", [])[:15],
            "pattern_templates": intelligence.get("pattern_templates", [])[:10],
            "cap_style": cap_style,
            "avg_length": avg_length,
            "preferred_separators": pref_seps,
            "rare_separators": intelligence.get("rare_separators", []),
            "strength_tier": strength,
            "leet_usage_pct": leet_pct,
            "leet_map": intelligence.get("leet_map", {}),
            "glue_words": intelligence.get("glue_words", [])[:10],
            "semantic_templates": intelligence.get("semantic_templates", [])[:10],
            "category_weights": cat_weights,
        }

        prompt = CODE_GENERATION_PROMPT.format(
            intelligence_json=json.dumps(compact_intel, separators=(",", ":")),
            strength_tier=strength,
            strength_guidance=strength_guidance,
            leet_pct=leet_pct,
            leet_guidance=leet_guidance,
            preferred_seps=json.dumps(pref_seps),
            avg_length=avg_length,
            top_categories=top_categories,
            cap_style=cap_style,
            theme_specific_instructions="\n".join(theme_lines),
        )

        response = self._message(prompt, temperature=0.3, max_tokens=8192)
        code = self._extract_code(response)

        if "def generate_all" not in code:
            log.warning("LLM code generation did not produce generate_all() — using fallback")
            return ""

        return code
