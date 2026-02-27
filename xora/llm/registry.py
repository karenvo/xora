"""Provider registry — resolves provider strings to LLMProvider instances."""

from __future__ import annotations

import logging
import os

import httpx

from xora.llm.base import LLMProvider

log = logging.getLogger(__name__)


def _ollama_available(base_url: str = "http://localhost:11434") -> str | None:
    """Check if Ollama is running and has at least one model. Returns model name or None."""
    try:
        resp = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=2)
        if resp.status_code != 200:
            return None
        data = resp.json()
        models = data.get("models", [])
        if not models:
            return None
        return models[0].get("name", models[0].get("model"))
    except (httpx.ConnectError, httpx.TimeoutException, OSError, ValueError):
        return None


def get_provider(
    provider_str: str,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    temperature: float = 0.7,
) -> LLMProvider:
    """Resolve a provider string like 'ollama/llama3.1:8b' into an LLMProvider.

    Supported formats:
        ollama                      -> Ollama with default model
        ollama/llama3.1:8b          -> Ollama with specific model
        anthropic                   -> Claude with default model
        anthropic/claude-sonnet-4-20250514  -> Claude with specific model
    """
    parts = provider_str.split("/", 1)
    backend = parts[0].lower().strip()
    model = parts[1].strip() if len(parts) > 1 else None

    if backend == "ollama":
        from xora.llm.ollama import OllamaProvider

        ollama_url = base_url or "http://localhost:11434"
        kwargs: dict = {"temperature": temperature, "base_url": ollama_url}
        if model:
            kwargs["model"] = model
        else:
            detected = _ollama_available(ollama_url)
            if detected:
                kwargs["model"] = detected
        return OllamaProvider(**kwargs)

    if backend in ("anthropic", "claude"):
        from xora.llm.anthropic_provider import AnthropicProvider

        kwargs = {"temperature": temperature}
        if model:
            kwargs["model"] = model
        if api_key:
            kwargs["api_key"] = api_key
        return AnthropicProvider(**kwargs)

    raise ValueError(
        f"Unknown LLM provider: {backend!r}. "
        f"Supported: ollama, anthropic"
    )


def auto_resolve(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    temperature: float = 0.7,
) -> tuple[LLMProvider | None, str]:
    """Auto-detect the best available LLM provider.

    Priority:
        1. Local Ollama (no data leaves the machine)
        2. Anthropic Claude (if ANTHROPIC_API_KEY or XORA_API_KEY is set)
        3. None (fall back to rule-based only)

    Returns (provider, provider_name) or (None, "none").
    """
    ollama_url = base_url or "http://localhost:11434"

    # Try Ollama first
    ollama_model = _ollama_available(ollama_url)
    if ollama_model:
        log.debug("Ollama detected at %s with model %s", ollama_url, ollama_model)
        from xora.llm.ollama import OllamaProvider

        provider = OllamaProvider(model=ollama_model, base_url=ollama_url, temperature=temperature)
        # Verify the model actually works with a tiny probe
        try:
            resp = httpx.post(
                f"{ollama_url}/api/generate",
                json={"model": ollama_model, "prompt": "hi", "stream": False,
                      "options": {"num_predict": 1}},
                timeout=10,
            )
            resp.raise_for_status()
            return provider, f"ollama/{ollama_model} (local)"
        except Exception:
            log.debug("Ollama model %s failed probe, skipping", ollama_model)

    # Try Anthropic
    resolved_key = api_key or os.environ.get("XORA_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if resolved_key:
        log.debug("Falling back to Anthropic (API key found)")
        from xora.llm.anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=resolved_key, temperature=temperature), "anthropic/claude"

    return None, "none"
