"""Ollama (local LLM) provider."""

from __future__ import annotations

import json
import logging

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
    TARGETED_CANDIDATES_PROMPT,
    _parse_candidates_response,
)

log = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    """Connect to a local Ollama instance."""

    def __init__(
        self,
        model: str | None = None,
        base_url: str = "http://localhost:11434",
        temperature: float = 0.7,
        timeout: float = 120,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model or self._detect_model()
        self.temperature = temperature
        self.timeout = timeout
        self._client = httpx.Client(timeout=self.timeout)

    def _detect_model(self) -> str:
        """Query Ollama for the first available model."""
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=3)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                if models:
                    return models[0].get("name", models[0].get("model"))
        except (httpx.ConnectError, httpx.TimeoutException, OSError, ValueError):
            pass
        raise RuntimeError(
            "No Ollama models found. Pull one first: ollama pull llama3.1"
        )

    def generate_text(self, prompt: str, temperature: float | None = None,
                      max_tokens: int | None = None) -> str:
        return self._generate(prompt, temperature)

    def extract_json(self, text: str) -> str:
        return self._extract_json(text)

    _JSON_SYSTEM = (
        "You are a data extraction assistant. Always respond with valid JSON "
        "only — no markdown fences, no commentary, no explanation."
    )

    def _generate(self, prompt: str, temperature: float | None = None,
                  system: str | None = None) -> str:
        """Send a generate request to Ollama and return the response text."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature if temperature is not None else self.temperature,
            },
        }
        if system:
            payload["system"] = system
        log.debug("Ollama request model=%s", self.model)
        resp = self._client.post(f"{self.base_url}/api/generate", json=payload)
        if resp.status_code != 200:
            try:
                body = resp.json()
                err_msg = body.get("error", "")
            except Exception:
                err_msg = resp.text
            if "memory" in err_msg.lower():
                raise RuntimeError(
                    f"Ollama: not enough memory to load {self.model}. "
                    f"Close other apps, use a smaller model "
                    f"(e.g. ollama pull phi3:mini), or use --no-llm."
                )
            resp.raise_for_status()
        return resp.json()["response"]

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
                                "Ollama %s response was truncated — salvaged %d entries",
                                label, len(salvaged),
                            )
                            return salvaged
                    except json.JSONDecodeError:
                        pass
            log.warning("Failed to parse Ollama %s as JSON", label)
            return []

    # ------------------------------------------------------------------
    # LLM method implementations
    # ------------------------------------------------------------------

    def parse_profile(self, raw_text: str) -> dict:
        prompt = PROFILE_PARSE_PROMPT.format(raw_text=raw_text)
        response = self._generate(prompt, system=self._JSON_SYSTEM)
        try:
            return json.loads(self._extract_json(response))
        except json.JSONDecodeError:
            log.warning("Failed to parse Ollama profile response as JSON")
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
            self._generate(prompt, system=self._JSON_SYSTEM), "password suggestions"
        )

    def analyze_patterns(self, passwords: list[str]) -> list[dict]:
        prompt = PATTERN_ANALYZE_PROMPT.format(passwords="\n".join(passwords))
        response = self._generate(prompt, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            log.warning("Failed to parse Ollama pattern analysis as JSON")
            return []

    def categorize_passwords(self, passwords: list[str], decoded_passwords: list[dict]) -> list[dict]:
        lines = "\n".join(
            f"  {d['original']} → {d['decoded']}" for d in decoded_passwords
        )
        prompt = PASSWORD_CATEGORIZE_PROMPT.format(passwords_list=lines)
        response = self._generate(prompt, system=self._JSON_SYSTEM)
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
            log.warning("Failed to parse Ollama password categorization as JSON")
            return []

    def cross_reference(self, raw_text: str, llm_data: dict, parser_data: dict) -> dict:
        prompt = CROSS_REFERENCE_PROMPT.format(
            raw_text=raw_text,
            llm_json=json.dumps(llm_data, indent=2),
            parser_json=json.dumps(parser_data, indent=2),
        )
        response = self._generate(prompt, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            return result if isinstance(result, dict) else {}
        except json.JSONDecodeError:
            log.warning("Failed to parse Ollama cross-reference response as JSON")
            return {}

    def infer_from_profile(self, profile_data: dict) -> list[dict]:
        prompt = PROFILE_INFERENCE_PROMPT.format(
            profile_json=json.dumps(profile_data, indent=2),
        )
        response = self._generate(prompt, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            log.warning("Failed to parse Ollama inference response as JSON")
            return []

    def correlate_passwords_and_profile(
        self, decoded_passwords: list[dict], profile_data: dict, inferred: list[dict]
    ) -> list[dict]:
        prompt = CORRELATION_ANALYSIS_PROMPT.format(
            passwords_json=json.dumps(decoded_passwords, indent=2),
            profile_json=json.dumps(profile_data, indent=2),
            inferred_json=json.dumps(inferred, indent=2),
        )
        response = self._generate(prompt, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            log.warning("Failed to parse Ollama correlation response as JSON")
            return []

    def curate_base_words(self, profile_data: dict, known_passwords: list[str]) -> dict:
        prompt = BASE_WORDS_CURATE_PROMPT.format(
            known_passwords="\n".join(known_passwords) if known_passwords else "(none available)",
            profile_json=json.dumps(profile_data, indent=2),
        )
        response = self._generate(prompt, system=self._JSON_SYSTEM)
        try:
            result = json.loads(self._extract_json(response))
            if isinstance(result, dict) and "base_words" in result:
                return result
            if isinstance(result, list):
                return {"base_words": [str(w) for w in result], "reasoning": ""}
            return {"base_words": [], "reasoning": ""}
        except json.JSONDecodeError:
            log.warning("Failed to parse Ollama base words curation as JSON")
            return {"base_words": [], "reasoning": ""}

    # ------------------------------------------------------------------
    # Targeted candidate generation
    # ------------------------------------------------------------------

    def generate_targeted_candidates(
        self,
        intelligence: dict,
    ) -> list[str]:
        """Generate psychologically-targeted password candidates as a JSON list."""
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

        strength_guidance = {
            "weak": "suggest simple guesses: single words + short numbers",
            "strong": "suggest complex guesses: multi-word compounds, leet-heavy, separators",
        }.get(strength, "suggest balanced guesses: word + separator + number combos")

        leet_guidance = (
            "apply aggressive leet to most candidates" if leet_pct >= 0.5 else
            "apply selective leet to about half the candidates" if leet_pct >= 0.2 else
            "minimal leet — keep most passwords clean"
        )

        compact_intel = {
            "word_tier_samples": {k: v[:10] for k, v in word_tiers.items()},
            "known_passwords": intelligence.get("known_passwords", [])[:20],
            "pattern_templates": intelligence.get("pattern_templates", [])[:10],
            "cap_style": cap_style,
            "cap_patterns": intelligence.get("cap_patterns", {}),
            "avg_length": avg_length,
            "preferred_separators": pref_seps,
            "strength_tier": strength,
            "leet_usage_pct": leet_pct,
            "leet_map": intelligence.get("leet_map", {}),
            "glue_words": intelligence.get("glue_words", [])[:10],
            "semantic_templates": intelligence.get("semantic_templates", [])[:8],
            "category_weights": cat_weights,
            "derivation_chains": intelligence.get("derivation_chains", [])[:5],
        }

        prompt = TARGETED_CANDIDATES_PROMPT.format(
            intelligence_json=json.dumps(compact_intel, indent=2),
            strength_tier=strength,
            strength_guidance=strength_guidance,
            leet_pct=leet_pct,
            leet_guidance=leet_guidance,
            preferred_seps=json.dumps(pref_seps),
            avg_length=avg_length,
            top_categories=top_categories,
            cap_style=cap_style,
        )

        response = self._generate(prompt, temperature=0.4)
        return _parse_candidates_response(response)
