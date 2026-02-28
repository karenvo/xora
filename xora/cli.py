"""xora CLI — targeted password wordlist generator for red team engagements."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from xora import __version__
from xora.codegen import (
    _classify_words_into_tiers,
    _extract_separator_fingerprint,
    build_intelligence_summary,
    write_analysis_files,
    write_target_folder,
)
from xora.interactive import run_preview_session, run_review_session
from xora.password_profiler import (
    assess_strength_profile,
    build_password_profile,
    categorize_passwords_rule_based,
    cross_reference_profile,
    CategorizedPassword,
    deleet,
    deleet_to_words,
)
from xora.inference_engine import (
    Correlation,
    InferredData,
    find_correlations,
    find_correlations_llm,
    run_inference,
    run_inference_llm,
)
from xora.pattern_analyzer import analyze_passwords
from xora.semantic_analyzer import (
    analyze_semantics_llm,
    analyze_semantics_rule_based,
)
from xora.profile_parser import (
    is_password_file,
    parse_profile_file,
    parse_profile_text,
    profile_from_llm_data,
    TargetProfile,
    _parse_password_file,
)

console = Console(stderr=True)

XORA_DIR = Path.cwd()  # targets are created in the current working directory

BANNER = r"""[cyan]
  ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░  ░▒▓██████▓▒░
  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
   ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
    ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓████████▓▒░
   ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
  ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓██████▓▒░ ░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
[/cyan]
  [dim]targeted password generation[/dim]  [bold red]v{version}[/bold red]
"""


def _validate_generated_code(code: str) -> tuple[bool, str]:
    """Statically validate LLM-generated generate_all() code.

    Returns (ok, reason). If ok is False the code must NOT be used.
    """
    import ast
    import re as _re

    # 1. Must compile cleanly
    try:
        ast.parse(code)
    except SyntaxError as exc:
        return False, f"SyntaxError: {exc}"

    # 2. Must contain generate_all
    if "def generate_all" not in code:
        return False, "missing generate_all()"

    # 3. Must not redefine utility functions that live in the outer script
    _FORBIDDEN_REDEFS = [
        "_all_words", "case_variants", "leet_variants", "number_suffixes",
        "score_candidate", "passes_policy", "_weighted_seps",
    ]
    for fn in _FORBIDDEN_REDEFS:
        if _re.search(rf"^def {fn}\b", code, _re.MULTILINE):
            return False, f"redefines {fn}() which already exists in the script"

    # 4. Must not use LEET_MAP with a multi-character key (word-level access)
    #    Legitimate use: LEET_MAP[c], LEET_MAP[char], LEET_MAP.get(c, ...)
    #    Bad use: LEET_MAP[word], leet_map[word], LEET_MAP[leet_map[word]-1]
    bad_leet = _re.findall(
        r'[Ll][Ee][Ee][Tt]_?[Mm][Aa][Pp]\[([^\]]+)\]', code
    )
    for key_expr in bad_leet:
        key_expr = key_expr.strip()
        # Allow: single-char variable names (c, k, ch), string literals of 1 char
        if _re.fullmatch(r"[a-zA-Z_]\w*", key_expr):
            # variable name — flag if it looks like a word variable
            if key_expr.lower() in ("word", "w", "pw", "password", "base",
                                    "leet_map", "leet_word", "name"):
                return False, (
                    f"LEET_MAP accessed with word-level key '{key_expr}' — "
                    "LEET_MAP maps single characters, not words. "
                    "Use leet_variants(word) instead."
                )
        elif not _re.fullmatch(r"'[a-z0-9]'|\"[a-z0-9]\"", key_expr):
            # Not a single-char string literal — could be an expression like
            # random.randint(...) or len(...) which is also wrong
            if any(kw in key_expr for kw in ("randint", "len(", "index", "word", "pw")):
                return False, (
                    f"LEET_MAP accessed with expression '{key_expr}' — "
                    "use leet_variants(word) to leet-encode a whole word."
                )

    # 5. Must not contain bare import statements
    if _re.search(r"^\s*import\s+\w", code, _re.MULTILINE):
        return False, "contains bare import statement (all modules already imported)"
    if _re.search(r"^\s*from\s+\w+\s+import\b", code, _re.MULTILINE):
        return False, "contains from-import statement (all modules already imported)"

    # 6. Must not contain infinite/unbounded recursion
    #    Detect any inner function that calls itself unconditionally at the end
    inner_fns = _re.findall(r"def (_target_\w+|_gen_\w+|_build_\w+)\(", code)
    for fn in inner_fns:
        # If the last call in the function body is to itself with no early return guard,
        # it's almost certainly an infinite recursion
        fn_body = _re.search(
            rf"def {_re.escape(fn)}\(.*?\n((?:[ \t]+.*\n)*)", code
        )
        if fn_body:
            body = fn_body.group(1)
            if _re.search(rf"\b{_re.escape(fn)}\(", body):
                return False, (
                    f"{fn}() calls itself recursively — use a loop instead"
                )

    return True, "ok"


def _maybe_review_code(raw_code: str, provider, console) -> str:
    """Validate then ask the provider to review its own generated code.

    Always validates first with the static checker. If validation fails,
    the review pass is skipped and "" is returned so the fallback engine runs.
    After review, validates again before accepting.
    """
    ok, reason = _validate_generated_code(raw_code)
    if not ok:
        console.print(
            f"  [yellow]Generated code failed validation:[/] {reason}\n"
            "  [dim]Using built-in engine instead.[/dim]"
        )
        return ""

    try:
        console.print("  [dim]Running code review pass...[/dim]")
        reviewed = provider.review_generated_code(raw_code)
        ok2, reason2 = _validate_generated_code(reviewed)
        if not ok2:
            console.print(
                f"  [yellow]Reviewed code still invalid:[/] {reason2}\n"
                "  [dim]Using built-in engine instead.[/dim]"
            )
            return ""
        console.print("  [dim]Code review complete.[/dim]")
        return reviewed
    except Exception as exc:
        console.print(f"  [yellow]Code review failed:[/] {exc} — using built-in engine")
        return ""


def _target_dir(name: str) -> Path:
    return XORA_DIR / f"{name}-xora"


_PW_GLUE_WORDS: set[str] = {
    "the", "and", "for", "you", "can", "not", "are", "but", "was",
    "has", "had", "this", "that", "with", "from", "your", "have",
    "will", "all", "her", "him", "his", "its", "our", "she", "they",
    "who", "let", "get", "got", "put", "may", "yet", "nor", "son",
    "man", "men", "day", "way", "too", "also", "just", "than",
    "then", "now", "how", "out", "any", "own", "some", "here",
    "when", "why", "what", "which", "been", "does", "did", "each",
    "into", "only", "over", "such", "take", "than", "them", "very",
    "come", "could", "make", "like", "back", "again", "ever",
    "band", "rocks", "roll", "rock",
}


def _extract_pw_words(
    decoded_entries: list[dict],
    existing_extra: list[str],
) -> list[str]:
    """Extract meaningful unique words from decoded passwords.

    Filters out common English glue words and leet-decoder artifacts
    (e.g. 'Crewi' from 'Cr3w!' where ! → i at a boundary).
    """
    seen = {w.lower() for w in existing_extra}
    # Collect all decoded words so we can detect artifact variants
    all_pw_words: set[str] = set()
    for entry in decoded_entries:
        for w in entry["words"]:
            if len(w) >= 2 and w.isalpha():
                all_pw_words.add(w.lower())

    results: list[str] = []
    for entry in decoded_entries:
        for word in entry["words"]:
            low = word.lower()
            if len(word) < 3 or not word.isalpha():
                continue
            if low in seen or low in _PW_GLUE_WORDS:
                continue
            # Detect decoder artifacts: word ending in i/a/s where the
            # base form (without trailing char) also exists as a word
            if len(low) >= 4 and low[-1] in ("i", "a", "s"):
                base = low[:-1]
                if base in all_pw_words or base in seen:
                    continue
            seen.add(low)
            results.append(word)
    return results


def _resolve_llm(
    llm: str | None, api_key: str | None, no_llm: bool = False
) -> tuple:
    """Return (LLMProvider, provider_name) or (None, 'none').

    Behavior:
        --no-llm          -> skip LLM entirely
        --llm <provider>  -> use that specific provider
        (default)         -> auto-detect: try Ollama, then Anthropic, then skip
    """
    if no_llm:
        return None, "none"

    if llm:
        try:
            from xora.llm import get_provider

            provider = get_provider(llm, api_key=api_key)
            return provider, llm
        except Exception as exc:
            console.print(f"[yellow]Warning:[/] Could not initialize LLM ({exc})")
            console.print("[dim]Continuing with rule-based analysis only.[/dim]")
            return None, "none"

    # Auto-detect best available provider
    from xora.llm.registry import auto_resolve

    console.print("[dim]Auto-detecting LLM...[/dim]")
    provider, name = auto_resolve(api_key=api_key)
    if provider:
        console.print(f"  [green]Using {name}[/green]")
    else:
        console.print("  [dim]No LLM available — using rule-based analysis only.[/dim]")
        console.print("  [dim]Start Ollama or set XORA_API_KEY for LLM enhancement.[/dim]")
    return provider, name


def _check_cache(
    target_dir: Path,
    raw_text: str,
    llm_model: str,
) -> tuple[bool, TargetProfile | None, PatternAnalysis | None]:
    """Check if cached analysis results are still valid.

    Returns (use_cache, profile, analysis) — profile and analysis are
    populated only when use_cache is True.
    """
    cache_path = target_dir / "cache_meta.json"
    parsed_path = target_dir / "profile.parsed.json"
    analysis_path = target_dir / "analysis.json"

    if not all(p.exists() for p in (cache_path, parsed_path, analysis_path)):
        return False, None, None

    try:
        cache_meta = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False, None, None

    profile_hash = hashlib.sha256(raw_text.encode()).hexdigest()
    if cache_meta.get("profile_hash") != profile_hash:
        return False, None, None
    if cache_meta.get("llm_model") != llm_model:
        return False, None, None

    try:
        parsed_data = json.loads(parsed_path.read_text(encoding="utf-8"))
        analysis_data = json.loads(analysis_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False, None, None

    profile = profile_from_llm_data(parsed_data, raw_text)

    analysis = analyze_passwords(profile.known_passwords)
    analysis.password_profile = analysis_data.get("password_profile", {})
    analysis.semantic_analysis = analysis_data.get("semantic_analysis", {})
    analysis.inferred_data = analysis_data.get("inferred_data", [])
    analysis.correlation_data = analysis_data.get("correlation_data", [])
    analysis.strength_profile = analysis_data.get("strength_profile", {})

    # Restore inferred/correlation words into the profile's extra_words
    for item in analysis.inferred_data:
        word = item.get("word", "")
        if word and word not in profile.extra_words:
            profile.extra_words.append(word)
    for corr in analysis.correlation_data:
        for sw in corr.get("suggested_words", []):
            if sw and sw not in profile.extra_words:
                profile.extra_words.append(sw)

    # Restore curated words if present in parsed data
    curated = parsed_data.get("_curated_words")
    if curated:
        profile.set_curated_words(curated)

    return True, profile, analysis


def _parse_with_llm_crossref(
    raw_text: str,
    filepath: str | None,
    provider,
    llm_model: str,
) -> TargetProfile:
    """Parse a profile using the LLM-first + parser + cross-reference pipeline.

    Flow:
      1. LLM parses the raw file (primary)
      2. Regex parser also parses the raw file
      3. LLM cross-references both results against the raw text
      4. Fallback: if no LLM, parser alone; if cross-ref fails, merge manually
    """
    llm_data: dict | None = None
    parser_profile: TargetProfile | None = None

    # Step 1: LLM parses raw text
    if provider:
        console.print(f"[dim]LLM parsing raw text ({llm_model})...[/dim]")
        try:
            llm_data = provider.parse_profile(raw_text)
            if llm_data:
                console.print("  [green]LLM extraction complete.[/green]")
            else:
                console.print("  [yellow]LLM returned empty data.[/yellow]")
                llm_data = None
        except Exception as exc:
            console.print(f"  [yellow]LLM parsing failed:[/] {exc}")

    # Step 2: Regex parser also parses raw text
    console.print("[dim]Running rule-based parser...[/dim]")
    if filepath:
        parser_profile = parse_profile_file(filepath)
    else:
        parser_profile = parse_profile_text(raw_text)
    parser_data = parser_profile.to_dict()
    console.print("  [green]Parser extraction complete.[/green]")

    # Step 3: LLM cross-references both results
    if provider and llm_data:
        console.print("[dim]Cross-referencing extractions against raw text...[/dim]")
        try:
            merged = provider.cross_reference(raw_text, llm_data, parser_data)
            if merged:
                profile = profile_from_llm_data(merged, raw_text)
                console.print("  [green]Cross-reference complete — final profile built.[/green]")
                return profile
            else:
                console.print("  [yellow]Cross-reference returned empty — falling back to manual merge.[/yellow]")
        except Exception as exc:
            console.print(f"  [yellow]Cross-reference failed:[/] {exc}")
            console.print("  [dim]Falling back to manual merge.[/dim]")

        # Fallback: manual merge (LLM data as base, parser fills gaps)
        profile = profile_from_llm_data(llm_data, raw_text)
        _merge_into_profile(profile, parser_data)
        return profile

    # No LLM available: parser alone
    if not provider:
        console.print(
            "  [dim]No LLM available — using parser results only.\n"
            "  Start Ollama or set XORA_API_KEY for better extraction.[/dim]"
        )
    return parser_profile


def _merge_into_profile(profile: TargetProfile, source_data: dict) -> None:
    """Merge fields from source_data into profile, adding missing items."""
    for key in ["nicknames", "pet_names", "interests", "teams",
                "companies", "extra_words", "children_names",
                "known_passwords", "emails", "usernames",
                "phone_numbers", "important_dates"]:
        existing = set(getattr(profile, key, []))
        for item in source_data.get(key, []):
            if item and item not in existing:
                getattr(profile, key).append(item)
    if not profile.partner_name and source_data.get("partner_name"):
        profile.partner_name = source_data["partner_name"]
    if not profile.name and source_data.get("name"):
        profile.name = source_data["name"]
    if not profile.first_name and source_data.get("first_name"):
        profile.first_name = source_data["first_name"]
    if not profile.last_name and source_data.get("last_name"):
        profile.last_name = source_data["last_name"]
    if not profile.birthdate and source_data.get("birthdate"):
        profile.birthdate = source_data["birthdate"]


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="xora")
@click.pass_context
def cli(ctx):
    """xora — targeted password wordlist generator for red team engagements.

    Generate personalized, standalone Python scripts that produce high-probability
    password candidates based on target profiles and known password patterns.
    """
    if ctx.invoked_subcommand is None:
        console.print(BANNER.format(version=__version__))
        console.print(ctx.get_help())


@cli.command()
@click.option("-n", "--name", required=True, help="Target name (used as folder prefix)")
@click.option("-f", "--file", "filepath", required=True, type=click.Path(exists=True),
              help="Path to free-text profile file")
@click.option("--llm", default=None,
              help="LLM provider (e.g. ollama/llama3.1:8b, anthropic/claude-sonnet-4-20250514)")
@click.option("--no-llm", is_flag=True, default=False,
              help="Skip LLM entirely — use rule-based analysis only")
@click.option("--api-key", default=None, envvar="XORA_API_KEY",
              help="API key for cloud LLM providers (or set XORA_API_KEY)")
@click.option("--passwords", "input_type", flag_value="passwords",
              help="Treat input as a plain password list (skip profile parsing)")
@click.option("--profile-file", "input_type", flag_value="profile",
              help="Treat input as a profile/OSINT file (override auto-detection)")
@click.option("--yes", "-y", "skip_review", is_flag=True, default=False,
              help="Skip interactive review and generate immediately")
@click.option("--min-length", default=8, show_default=True, type=int,
              help="Minimum password length baked into the generated script")
@click.option("--max-length", default=64, show_default=True, type=int,
              help="Maximum password length baked into the generated script")
@click.option("--require-upper", is_flag=True, default=False,
              help="Require at least one uppercase letter (default: off)")
@click.option("--require-lower", is_flag=True, default=False,
              help="Require at least one lowercase letter (default: off)")
@click.option("--require-digit", is_flag=True, default=False,
              help="Require at least one digit (default: off)")
@click.option("--require-special", is_flag=True, default=False,
              help="Require at least one special character (default: off)")
@click.option("--specials", default=None,
              help="Custom special characters to use (e.g. '!@#$%%^&*'). Default: !@#$%%1")
def add(
    name: str,
    filepath: str,
    llm: str | None,
    no_llm: bool,
    api_key: str | None,
    input_type: str | None,
    skip_review: bool,
    min_length: int,
    max_length: int,
    require_upper: bool,
    require_lower: bool,
    require_digit: bool,
    require_special: bool,
    specials: str | None,
):
    """Create a new target profile and generate a password script.

    By default, xora auto-detects the best LLM: tries local Ollama first,
    then falls back to Anthropic if an API key is set, and finally runs
    rule-based only if neither is available.

    \b
    Password policy defaults (override with flags):
      --min-length       8    (minimum password length)
      --max-length       64   (maximum password length)
      --require-upper    off  (require uppercase letter)
      --require-lower    off  (require lowercase letter)
      --require-digit    off  (require digit)
      --require-special  off  (require special character)
      --specials         auto (from known passwords, or !@#$%1)
    """
    target_dir = _target_dir(name)
    if target_dir.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target_dir = XORA_DIR / f"{name}-xora-{stamp}"
        console.print(
            f"[yellow]Previous run exists.[/yellow] "
            f"Creating new version: [bold]{target_dir.name}[/bold]"
        )

    console.print(Panel(f"[bold cyan]xora[/bold cyan] — Adding target: [bold]{name}[/bold]"))

    raw_text = Path(filepath).read_text(encoding="utf-8")

    # Resolve LLM provider
    decoded_for_llm: list[dict] = []
    provider, llm_model = _resolve_llm(llm, api_key, no_llm)

    # Parse: password-file gets special handling; everything else goes
    # through LLM-first → parser → LLM cross-reference pipeline
    if input_type == "passwords":
        pw_only = True
        console.print("[dim]--passwords flag: treating input as password list.[/dim]")
    elif input_type == "profile":
        pw_only = False
        console.print("[dim]--profile-file flag: treating input as OSINT profile.[/dim]")
    else:
        pw_only = is_password_file(raw_text)

    if pw_only:
        console.print("[dim]Detected password list — extracting credentials...[/dim]")
        profile = _parse_password_file(raw_text)
        if provider:
            console.print(f"[dim]Enhancing with LLM ({llm_model})...[/dim]")
            try:
                llm_data = provider.parse_profile(raw_text)
                if llm_data:
                    _merge_into_profile(profile, llm_data)
                    console.print("  [green]LLM-enhanced data merged.[/green]")
            except Exception as exc:
                console.print(f"  [yellow]LLM enhancement failed:[/] {exc}")
    else:
        profile = _parse_with_llm_crossref(raw_text, filepath, provider, llm_model)

    console.print(f"  Raw words extracted: [green]{len(profile.all_base_words())}[/green]")
    console.print(f"  Numbers extracted: [green]{len(profile.all_numbers())}[/green]")
    console.print(f"  Known passwords: [green]{len(profile.known_passwords)}[/green]")
    console.print(f"  Emails: [green]{len(profile.emails)}[/green]")

    # Analyze patterns from known passwords
    console.print("[dim]Analyzing password patterns...[/dim]")
    analysis = analyze_passwords(profile.known_passwords)
    if analysis.patterns:
        console.print(f"  Detected [green]{len(analysis.patterns)}[/green] pattern(s):")
        for pat in analysis.patterns:
            console.print(f"    [cyan]{pat.source}[/cyan] → {pat.template}")
    else:
        console.print("  [dim]No known passwords to analyze.[/dim]")

    # Decode leet speak + categorize passwords → build behavioral profile
    if profile.known_passwords:
        console.print("[dim]Decoding & categorizing passwords...[/dim]")
        decoded_for_llm = [
            {
                "original": pw,
                "decoded": deleet(pw),
                "words": deleet_to_words(pw),
            }
            for pw in profile.known_passwords
        ]

        # Extract decoded words from passwords into the base word pool.
        _pw_extracted = _extract_pw_words(decoded_for_llm, profile.extra_words)
        for w in _pw_extracted:
            profile.extra_words.append(w)
        if _pw_extracted:
            console.print(f"  Extracted [green]{len(_pw_extracted)}[/green] unique words from decoded passwords")

        # --- Parallel batch: categorize, semantics, inference, strength ---
        # These 4 tasks all depend only on profile/decoded_for_llm, not each other.
        categorized: list[CategorizedPassword] = []
        sem = None
        inferred: list[InferredData] = []
        strength = None
        profile_dict = profile.to_dict()

        if pw_only:
            console.print("[dim]Password-only input — skipping inference, correlation & semantics.[/dim]")

        if provider:
            console.print("[dim]Running parallel analysis (categorize + strength)...[/dim]")
            fut_inf = None
            fut_sem = None
            with ThreadPoolExecutor(max_workers=4) as pool:
                fut_cat = pool.submit(
                    provider.categorize_passwords,
                    profile.known_passwords, decoded_for_llm,
                )
                if not pw_only:
                    fut_sem = pool.submit(
                        analyze_semantics_llm,
                        decoded_for_llm, profile_dict, provider,
                    )
                    fut_inf = pool.submit(
                        run_inference_llm, profile_dict, provider,
                    )
                fut_str = pool.submit(
                    assess_strength_profile, profile.known_passwords,
                )

            # Collect categorization
            try:
                llm_cats = fut_cat.result()
                if llm_cats:
                    for item in llm_cats:
                        orig = item.get("original", "")
                        match = next((d for d in decoded_for_llm
                                      if d["original"] == orig), None)
                        categorized.append(CategorizedPassword(
                            original=orig,
                            decoded=match["decoded"] if match else orig,
                            words=match["words"] if match else [],
                            category=item.get("category", "unknown"),
                            confidence=item.get("confidence", 0.0),
                        ))
                    console.print(f"  [green]LLM categorized {len(categorized)} passwords.[/green]")
            except Exception as exc:
                console.print(f"  [yellow]LLM categorization failed:[/] {exc}")

            # Collect semantics (skipped for password-only input)
            if fut_sem is not None:
                try:
                    sem = fut_sem.result()
                except Exception as exc:
                    console.print(f"  [yellow]LLM semantic decomposition failed:[/] {exc}")

            # Collect inference (skipped for password-only input)
            if fut_inf is not None:
                try:
                    inferred = fut_inf.result()
                except Exception as exc:
                    console.print(f"  [yellow]LLM inference failed:[/] {exc}")

            # Collect strength (CPU-bound, should never fail)
            strength = fut_str.result()
        else:
            if not pw_only:
                sem = analyze_semantics_rule_based(decoded_for_llm, profile_dict)
                inferred = run_inference(profile_dict)
            strength = assess_strength_profile(profile.known_passwords)

        # --- Process categorization results ---
        if not categorized:
            categorized = categorize_passwords_rule_based(profile.known_passwords)
            console.print(f"  Categorized {len(categorized)} passwords (rule-based).")

        pw_profile = build_password_profile(
            categorized,
            structural_habits={
                "capitalization": analysis.capitalization_style,
                "number_style": analysis.number_style,
                "avg_length": f"{analysis.avg_length:.1f}",
            },
        )

        priority_weights = cross_reference_profile(pw_profile, profile.to_dict())
        pw_profile_dict = pw_profile.to_dict()
        pw_profile_dict["priority_weights"] = priority_weights
        analysis.password_profile = pw_profile_dict

        if pw_profile.top_categories:
            console.print(f"  Top themes: [bold cyan]{', '.join(pw_profile.top_categories[:5])}[/bold cyan]")
        for cat, pct in list(pw_profile.category_distribution.items())[:5]:
            bar = "█" * int(pct * 30)
            console.print(f"    {cat:<14} {pct:>5.1%}  [dim]{bar}[/dim]")

        # --- Process semantic results ---
        if sem is None and decoded_for_llm:
            sem = analyze_semantics_rule_based(decoded_for_llm, profile_dict)
        if sem:
            analysis.semantic_analysis = sem.to_dict()
            if sem.glue_words:
                console.print(
                    f"  Glue words: [bold green]{', '.join(sem.glue_words[:10])}[/bold green]"
                )
            if sem.semantic_templates:
                console.print(
                    f"  Semantic templates: [cyan]{len(sem.semantic_templates)}[/cyan] unique"
                )
                for tmpl in sem.semantic_templates[:5]:
                    console.print(f"    [dim]{tmpl}[/dim]")
                if len(sem.semantic_templates) > 5:
                    console.print(f"    [dim]... and {len(sem.semantic_templates) - 5} more[/dim]")
            if sem.role_vocabulary:
                for role, words in list(sem.role_vocabulary.items())[:5]:
                    console.print(
                        f"    [yellow]{role}[/yellow]: {', '.join(words[:6])}"
                        f"{'...' if len(words) > 6 else ''}"
                    )

        # --- Process strength results ---
        if strength:
            analysis.strength_profile = strength.to_dict()
            tier_colors = {"weak": "red", "moderate": "yellow", "strong": "green"}
            tc = tier_colors.get(strength.tier, "white")
            console.print(
                f"  Overall strength: [{tc}][bold]{strength.tier.upper()}[/bold][/{tc}] "
                f"(avg score: {strength.avg_score:.2f})"
            )
            console.print(
                f"    Length range: {strength.min_length}-{strength.max_length} "
                f"(avg {strength.avg_length:.0f}) | "
                f"Char classes: {strength.avg_char_classes:.1f}/4 | "
                f"Entropy: {strength.avg_entropy:.0f} bits"
            )
            if strength.leet_usage_pct > 0:
                console.print(f"    Leet speak: {strength.leet_usage_pct:.0%} of passwords")
            if strength.reuse_ratio > 0:
                console.print(f"    Word reuse: {strength.reuse_ratio:.0%} of passwords share base words")
            if strength.common_weaknesses:
                console.print(f"    Common weaknesses: [dim]{', '.join(strength.common_weaknesses)}[/dim]")

            for s in strength.individual:
                stc = tier_colors.get(s.tier, "white")
                console.print(
                    f"      [{stc}]{s.tier:<8}[/{stc}] "
                    f"[dim]{s.score:.2f}[/dim]  {s.password}"
                )

        # --- Process inference results ---
        if inferred:
            for item in inferred:
                if item.word and item.word not in profile.extra_words:
                    profile.extra_words.append(item.word)
            console.print(f"  [green]Inferred {len(inferred)} additional words[/green]")
            for item in inferred[:8]:
                console.print(f"    [cyan][{item.rule}][/cyan] {item.word} — [dim]{item.reasoning}[/dim]")
            if len(inferred) > 8:
                console.print(f"    [dim]... and {len(inferred) - 8} more[/dim]")
        else:
            console.print("  [dim]No additional words inferred.[/dim]")

        # --- Correlation (sequential — needs inference results, skip for pw_only) ---
        correlations: list[Correlation] = []
        if not pw_only:
            decoded_for_corr = decoded_for_llm
            if decoded_for_corr or inferred:
                console.print("[dim]Analyzing correlations...[/dim]")
                if provider:
                    correlations = find_correlations_llm(
                        decoded_for_corr, profile.to_dict(), inferred, provider
                    )
                else:
                    correlations = find_correlations(
                        decoded_for_corr, profile.to_dict(), inferred
                    )

                if correlations:
                    console.print(f"  [green]Found {len(correlations)} correlation(s)[/green]")
                    for corr in correlations[:5]:
                        console.print(
                            f"    [bold yellow]{corr.pattern_name}[/bold yellow] "
                            f"— {corr.insight[:80]}{'...' if len(corr.insight) > 80 else ''}"
                        )
                        if corr.suggested_words:
                            for sw in corr.suggested_words:
                                if sw and sw not in profile.extra_words:
                                    profile.extra_words.append(sw)
                else:
                    console.print("  [dim]No correlations found.[/dim]")

    else:
        # No known passwords — still run inference for profiles (unless pw_only)
        inferred: list[InferredData] = []
        correlations: list[Correlation] = []
        if not pw_only and provider:
            try:
                inferred = run_inference_llm(profile.to_dict(), provider)
                if inferred:
                    for item in inferred:
                        if item.word and item.word not in profile.extra_words:
                            profile.extra_words.append(item.word)
            except Exception:
                pass

    # Store inference and correlation data in analysis
    analysis.inferred_data = [
        {"word": i.word, "rule": i.rule, "source": i.source,
         "confidence": i.confidence, "reasoning": i.reasoning}
        for i in inferred
    ]
    analysis.correlation_data = [c.to_dict() for c in correlations]

    # Curate base words: LLM analyzes profile vs known passwords
    raw_word_count = len(profile.all_base_words())
    if provider:
        console.print("[dim]Curating base words with LLM...[/dim]")
        try:
            curation = provider.curate_base_words(
                profile.to_dict(), profile.known_passwords
            )
            curated = curation.get("base_words", [])
            reasoning = curation.get("reasoning", "")
            if curated:
                profile.set_curated_words(curated)
                console.print(
                    f"  [green]Curated {len(curated)} base words[/green] "
                    f"(from {raw_word_count} raw)"
                )
                if reasoning:
                    console.print(f"  [dim]{reasoning}[/dim]")
            else:
                console.print("  [yellow]LLM returned empty curation — using filtered fallback.[/yellow]")
        except Exception as exc:
            console.print(f"  [yellow]LLM curation failed:[/] {exc}")
            console.print("  [dim]Using basic noise filter instead.[/dim]")

    console.print(f"  Final base words: [green]{len(profile.all_base_words())}[/green]")

    # --- Save analysis files (no codegen yet) ---
    tiers = _classify_words_into_tiers(profile, analysis)
    write_analysis_files(
        target_dir, profile, analysis,
        target_name=name, llm_model=llm_model, raw_text=raw_text,
    )

    # --- Interactive review ---
    review = run_review_session(
        profile, analysis, tiers, target_dir,
        min_length=min_length, max_length=max_length,
        require_upper=require_upper, require_lower=require_lower,
        require_digit=require_digit, require_special=require_special,
        specials=specials, provider=provider,
    ) if not skip_review else {
        "min_length": min_length, "max_length": max_length,
        "require_upper": require_upper, "require_lower": require_lower,
        "require_digit": require_digit, "require_special": require_special,
        "specials": specials, "leet_override": None,
    }

    min_length = review["min_length"]
    max_length = review["max_length"]
    require_upper = review["require_upper"]
    require_lower = review["require_lower"]
    require_digit = review["require_digit"]
    require_special = review["require_special"]
    specials = review["specials"]
    leet_override = review.get("leet_override")
    leet_exhaustive = review.get("leet_exhaustive", False)

    # --- LLM-driven targeted candidate generation + code generation ---
    llm_candidates: list[str] | None = None
    custom_code: str | None = None

    if provider:
        intel = build_intelligence_summary(profile, analysis)
        intel["decoded_passwords"] = decoded_for_llm
        intel["profile_data"] = profile.to_dict()
        intel["correlation_insights"] = analysis.correlation_data or []
        intel["derivation_chains"] = [c.to_dict() for c in analysis.derivation_chains]

        console.print("[dim]LLM: Generating targeted password candidates...[/dim]")
        try:
            llm_candidates = provider.generate_targeted_candidates(intel)
            if llm_candidates:
                console.print(
                    f"  [green]LLM contributed {len(llm_candidates)} targeted candidates.[/green]"
                )
            else:
                console.print("  [yellow]LLM returned no candidates — engine will use word pool only.[/yellow]")
        except Exception as exc:
            console.print(f"  [yellow]LLM candidate generation failed:[/] {exc}")
            console.print("  [dim]Engine will use word pool only.[/dim]")

        console.print("[dim]LLM: Generating custom generation engine...[/dim]")
        try:
            raw_code = provider.generate_custom_code(intel)
            if raw_code:
                custom_code = _maybe_review_code(raw_code, provider, console)
                console.print("  [green]Custom generation engine ready.[/green]")
            else:
                console.print("  [yellow]LLM skipped code generation — using built-in engine.[/yellow]")
        except Exception as exc:
            console.print(f"  [yellow]LLM code generation failed:[/] {exc}")
            console.print("  [dim]Using built-in combinatorial engine.[/dim]")
    else:
        console.print(
            "[yellow]No LLM available — using combinatorial engine only. "
            "For better results, rerun with: --llm ollama[/yellow]"
        )

    # --- Preview & select ---
    tiers, llm_candidates = run_preview_session(
        tiers, llm_candidates, analysis, skip=skip_review,
    )

    console.print("[dim]Generating target folder...[/dim]")
    result_dir = write_target_folder(
        target_dir,
        profile,
        analysis,
        target_name=name,
        llm_model=llm_model,
        llm_candidates=llm_candidates,
        custom_code=custom_code,
        raw_text=raw_text,
        min_length=min_length,
        max_length=max_length,
        require_upper=require_upper,
        require_lower=require_lower,
        require_digit=require_digit,
        require_special=require_special,
        custom_specials=specials,
        leet_override=leet_override,
        leet_exhaustive=leet_exhaustive,
    )

    console.print()
    console.print(Panel.fit(
        f"[bold green]Target created:[/bold green] {result_dir}\n\n"
        f"  [bold]profile.raw[/bold]            — original profile text\n"
        f"  [bold]profile.parsed.json[/bold]    — structured extracted data\n"
        f"  [bold]analysis.json[/bold]          — pattern analysis data\n"
        f"  [bold]analysis.md[/bold]            — human-readable report\n"
        f"  [bold]generate_passwords.py[/bold]  — standalone password generator\n\n"
        f"Run the generator:\n"
        f"  [cyan]python3 {result_dir}/generate_passwords.py[/cyan]\n"
        f"  [cyan]python3 {result_dir}/generate_passwords.py --ranked -o wordlist.txt[/cyan]\n"
        f"  [cyan]python3 {result_dir}/generate_passwords.py | hydra -l user -P /dev/stdin ...[/cyan]",
        title="[bold]Done[/bold]",
    ))


@cli.command()
@click.option("-n", "--name", required=True, help="Target name")
@click.option("--llm", default=None,
              help="LLM provider for re-analysis")
@click.option("--no-llm", is_flag=True, default=False,
              help="Skip LLM entirely — use rule-based analysis only")
@click.option("--no-cache", is_flag=True, default=False,
              help="Force full re-analysis, ignoring cached results")
@click.option("--api-key", default=None, envvar="XORA_API_KEY",
              help="API key for cloud LLM providers")
@click.option("--passwords", "input_type", flag_value="passwords",
              help="Treat profile.raw as a plain password list")
@click.option("--profile-file", "input_type", flag_value="profile",
              help="Treat profile.raw as a profile/OSINT file (override auto-detection)")
@click.option("--yes", "-y", "skip_review", is_flag=True, default=False,
              help="Skip interactive review and generate immediately")
@click.option("--min-length", default=8, show_default=True, type=int,
              help="Minimum password length baked into the generated script")
@click.option("--max-length", default=64, show_default=True, type=int,
              help="Maximum password length baked into the generated script")
@click.option("--require-upper", is_flag=True, default=False,
              help="Require at least one uppercase letter (default: off)")
@click.option("--require-lower", is_flag=True, default=False,
              help="Require at least one lowercase letter (default: off)")
@click.option("--require-digit", is_flag=True, default=False,
              help="Require at least one digit (default: off)")
@click.option("--require-special", is_flag=True, default=False,
              help="Require at least one special character (default: off)")
@click.option("--specials", default=None,
              help="Custom special characters to use (e.g. '!@#$%%^&*'). Default: !@#$%%1")
def analyze(
    name: str,
    llm: str | None,
    no_llm: bool,
    no_cache: bool,
    api_key: str | None,
    input_type: str | None,
    skip_review: bool,
    min_length: int,
    max_length: int,
    require_upper: bool,
    require_lower: bool,
    require_digit: bool,
    require_special: bool,
    specials: str | None,
):
    """Re-analyze a target profile and regenerate the password script.

    By default, auto-detects the best LLM (Ollama -> Anthropic -> none).
    Cached analysis results are reused when the profile hasn't changed;
    use --no-cache to force a full re-run.

    \b
    Password policy defaults (override with flags):
      --min-length       8    (minimum password length)
      --max-length       64   (maximum password length)
      --require-upper    off  (require uppercase letter)
      --require-lower    off  (require lowercase letter)
      --require-digit    off  (require digit)
      --require-special  off  (require special character)
      --specials         auto (from known passwords, or !@#$%1)
    """
    target_dir = _target_dir(name)
    if not target_dir.exists():
        console.print(f"[red]Error:[/] Target folder [bold]{target_dir}[/bold] not found.")
        console.print("Use [bold]xora add[/bold] to create a target first.")
        raise SystemExit(1)

    raw_path = target_dir / "profile.raw"
    if not raw_path.exists():
        console.print(f"[red]Error:[/] No profile.raw found in {target_dir}")
        raise SystemExit(1)

    console.print(Panel(f"[bold cyan]xora[/bold cyan] — Re-analyzing: [bold]{name}[/bold]"))

    raw_text = raw_path.read_text(encoding="utf-8")

    # Resolve LLM provider
    decoded_for_llm: list[dict] = []
    provider, llm_model = _resolve_llm(llm, api_key, no_llm)

    if input_type == "passwords":
        pw_only = True
        console.print("[dim]--passwords flag: treating input as password list.[/dim]")
    elif input_type == "profile":
        pw_only = False
        console.print("[dim]--profile-file flag: treating input as OSINT profile.[/dim]")
    else:
        pw_only = is_password_file(raw_text)

    # --- Cache check: skip LLM analysis steps if profile is unchanged ---
    use_cache = False
    if not no_cache:
        use_cache, cached_profile, cached_analysis = _check_cache(
            target_dir, raw_text, llm_model,
        )
        if use_cache:
            console.print("[dim]Loading cached analysis (profile unchanged)...[/dim]")
            profile = cached_profile
            analysis = cached_analysis
            console.print(f"  Base words: [green]{len(profile.all_base_words())}[/green]")
            console.print(f"  Known passwords: [green]{len(profile.known_passwords)}[/green]")
            console.print(
                f"  [dim]Skipped 7 analysis steps — "
                f"rerun with --no-cache to force full re-analysis.[/dim]"
            )
            # Build decoded_for_llm for generation phases
            if profile.known_passwords:
                decoded_for_llm = [
                    {
                        "original": pw,
                        "decoded": deleet(pw),
                        "words": deleet_to_words(pw),
                    }
                    for pw in profile.known_passwords
                ]
        else:
            console.print("[dim]Profile changed — running full analysis...[/dim]")
    else:
        console.print("[dim]Cache disabled — running full analysis...[/dim]")

    if not use_cache:
        # --- Full analysis pipeline (no cache or cache invalid) ---

        # Parse: password-file gets special handling; everything else goes
        # through LLM-first → parser → LLM cross-reference pipeline
        if is_password_file(raw_text):
            console.print("[dim]Detected password list — extracting credentials...[/dim]")
            profile = _parse_password_file(raw_text)
            if provider:
                console.print(f"[dim]Enhancing with LLM ({llm_model})...[/dim]")
                try:
                    llm_data = provider.parse_profile(raw_text)
                    if llm_data:
                        _merge_into_profile(profile, llm_data)
                        console.print("  [green]LLM-enhanced data merged.[/green]")
                except Exception as exc:
                    console.print(f"  [yellow]LLM enhancement failed:[/] {exc}")
        else:
            profile = _parse_with_llm_crossref(raw_text, None, provider, llm_model)

        console.print(f"  Raw words extracted: [green]{len(profile.all_base_words())}[/green]")
        console.print(f"  Numbers: [green]{len(profile.all_numbers())}[/green]")
        console.print(f"  Known passwords: [green]{len(profile.known_passwords)}[/green]")

        analysis = analyze_passwords(profile.known_passwords)
        if analysis.patterns:
            console.print(f"  Detected [green]{len(analysis.patterns)}[/green] pattern(s)")

        # Decode leet speak + categorize passwords → build behavioral profile
        if profile.known_passwords:
            console.print("[dim]Decoding & categorizing passwords...[/dim]")
            decoded_for_llm = [
                {
                    "original": pw,
                    "decoded": deleet(pw),
                    "words": deleet_to_words(pw),
                }
                for pw in profile.known_passwords
            ]

            _pw_extracted = _extract_pw_words(decoded_for_llm, profile.extra_words)
            for w in _pw_extracted:
                profile.extra_words.append(w)
            if _pw_extracted:
                console.print(f"  Extracted [green]{len(_pw_extracted)}[/green] unique words from decoded passwords")

            # --- Parallel batch: categorize, semantics, inference, strength ---
            categorized: list[CategorizedPassword] = []
            sem = None
            inferred: list[InferredData] = []
            strength = None
            profile_dict = profile.to_dict()

            if pw_only:
                console.print("[dim]Password-only input — skipping inference, correlation & semantics.[/dim]")

            if provider:
                console.print("[dim]Running parallel analysis (categorize + strength)...[/dim]")
                fut_inf = None
                fut_sem = None
                with ThreadPoolExecutor(max_workers=4) as pool:
                    fut_cat = pool.submit(
                        provider.categorize_passwords,
                        profile.known_passwords, decoded_for_llm,
                    )
                    if not pw_only:
                        fut_sem = pool.submit(
                            analyze_semantics_llm,
                            decoded_for_llm, profile_dict, provider,
                        )
                        fut_inf = pool.submit(
                            run_inference_llm, profile_dict, provider,
                        )
                    fut_str = pool.submit(
                        assess_strength_profile, profile.known_passwords,
                    )

                # Collect categorization
                try:
                    llm_cats = fut_cat.result()
                    if llm_cats:
                        for item in llm_cats:
                            orig = item.get("original", "")
                            match = next((d for d in decoded_for_llm
                                          if d["original"] == orig), None)
                            categorized.append(CategorizedPassword(
                                original=orig,
                                decoded=match["decoded"] if match else orig,
                                words=match["words"] if match else [],
                                category=item.get("category", "unknown"),
                                confidence=item.get("confidence", 0.0),
                            ))
                        console.print(f"  [green]LLM categorized {len(categorized)} passwords.[/green]")
                except Exception as exc:
                    console.print(f"  [yellow]LLM categorization failed:[/] {exc}")

                # Collect semantics (skipped for password-only input)
                if fut_sem is not None:
                    try:
                        sem = fut_sem.result()
                    except Exception as exc:
                        console.print(f"  [yellow]LLM semantic decomposition failed:[/] {exc}")

                # Collect inference (skipped for password-only input)
                if fut_inf is not None:
                    try:
                        inferred = fut_inf.result()
                    except Exception as exc:
                        console.print(f"  [yellow]LLM inference failed:[/] {exc}")

                # Collect strength
                strength = fut_str.result()
            else:
                if not pw_only:
                    sem = analyze_semantics_rule_based(decoded_for_llm, profile_dict)
                    inferred = run_inference(profile_dict)
                strength = assess_strength_profile(profile.known_passwords)

            # --- Process categorization ---
            if not categorized:
                categorized = categorize_passwords_rule_based(profile.known_passwords)
                console.print(f"  Categorized {len(categorized)} passwords (rule-based).")

            pw_profile = build_password_profile(
                categorized,
                structural_habits={
                    "capitalization": analysis.capitalization_style,
                    "number_style": analysis.number_style,
                    "avg_length": f"{analysis.avg_length:.1f}",
                },
            )

            priority_weights = cross_reference_profile(pw_profile, profile.to_dict())
            pw_profile_dict = pw_profile.to_dict()
            pw_profile_dict["priority_weights"] = priority_weights
            analysis.password_profile = pw_profile_dict

            if pw_profile.top_categories:
                console.print(f"  Top themes: [bold cyan]{', '.join(pw_profile.top_categories[:5])}[/bold cyan]")

            # --- Process semantics ---
            if sem is None:
                sem = analyze_semantics_rule_based(decoded_for_llm, profile_dict)
            if sem:
                analysis.semantic_analysis = sem.to_dict()
                if sem.semantic_templates:
                    console.print(
                        f"  Semantic templates: [cyan]{len(sem.semantic_templates)}[/cyan] unique"
                    )

            # --- Process strength ---
            if strength:
                analysis.strength_profile = strength.to_dict()
                tier_colors = {"weak": "red", "moderate": "yellow", "strong": "green"}
                color = tier_colors.get(strength.tier, "white")
                console.print(
                    f"  Overall strength: [{color}]{strength.tier.upper()}[/{color}] "
                    f"(avg score: {strength.avg_score:.2f})"
                )

            # --- Process inference ---
            if inferred:
                for item in inferred:
                    if item.word and item.word not in profile.extra_words:
                        profile.extra_words.append(item.word)
                console.print(f"  [green]Inferred {len(inferred)} additional words[/green]")

            # --- Correlation (sequential — needs inference results, skip for pw_only) ---
            correlations: list[Correlation] = []
            if not pw_only:
                decoded_for_corr = decoded_for_llm
                if decoded_for_corr or inferred:
                    console.print("[dim]Analyzing correlations...[/dim]")
                    if provider:
                        correlations = find_correlations_llm(
                            decoded_for_corr, profile.to_dict(), inferred, provider
                        )
                    else:
                        correlations = find_correlations(
                            decoded_for_corr, profile.to_dict(), inferred
                        )
                    if correlations:
                        console.print(f"  [green]Found {len(correlations)} correlation(s)[/green]")
                        for corr in correlations[:5]:
                            console.print(
                                f"    [bold yellow]{corr.pattern_name}[/bold yellow] "
                                f"— {corr.insight[:80]}{'...' if len(corr.insight) > 80 else ''}"
                            )
                            if corr.suggested_words:
                                for sw in corr.suggested_words:
                                    if sw and sw not in profile.extra_words:
                                        profile.extra_words.append(sw)

            analysis.inferred_data = [
                {"word": i.word, "rule": i.rule, "source": i.source,
                 "confidence": i.confidence, "reasoning": i.reasoning}
                for i in inferred
            ]
            analysis.correlation_data = [c.to_dict() for c in correlations]

            # Curate base words
            raw_word_count = len(profile.all_base_words())
            if provider:
                console.print("[dim]Curating base words with LLM...[/dim]")
                try:
                    curation = provider.curate_base_words(
                        profile.to_dict(), profile.known_passwords
                    )
                    curated = curation.get("base_words", [])
                    reasoning = curation.get("reasoning", "")
                    if curated:
                        profile.set_curated_words(curated)
                        console.print(
                            f"  [green]Curated {len(curated)} base words[/green] "
                            f"(from {raw_word_count} raw)"
                        )
                    else:
                        console.print("  [yellow]LLM returned empty curation — using filtered fallback.[/yellow]")
                except Exception as exc:
                    console.print(f"  [yellow]LLM curation failed:[/] {exc}")

        console.print(f"  Final base words: [green]{len(profile.all_base_words())}[/green]")

    # --- Save analysis files (no codegen yet) ---
    cached_steps = ["parse", "categorize", "semantics", "curate"]
    if not pw_only:
        cached_steps[3:3] = ["inference", "correlations"]
    tiers = _classify_words_into_tiers(profile, analysis)
    write_analysis_files(
        target_dir, profile, analysis,
        target_name=name, llm_model=llm_model, raw_text=raw_text,
        cached_steps=cached_steps,
    )

    # --- Interactive review ---
    review = run_review_session(
        profile, analysis, tiers, target_dir,
        min_length=min_length, max_length=max_length,
        require_upper=require_upper, require_lower=require_lower,
        require_digit=require_digit, require_special=require_special,
        specials=specials, provider=provider,
    ) if not skip_review else {
        "min_length": min_length, "max_length": max_length,
        "require_upper": require_upper, "require_lower": require_lower,
        "require_digit": require_digit, "require_special": require_special,
        "specials": specials, "leet_override": None,
    }

    min_length = review["min_length"]
    max_length = review["max_length"]
    require_upper = review["require_upper"]
    require_lower = review["require_lower"]
    require_digit = review["require_digit"]
    require_special = review["require_special"]
    specials = review["specials"]
    leet_override = review.get("leet_override")
    leet_exhaustive = review.get("leet_exhaustive", False)

    # --- LLM-driven targeted candidate generation + code generation ---
    llm_candidates: list[str] | None = None
    custom_code: str | None = None

    if provider:
        intel = build_intelligence_summary(profile, analysis)
        intel["decoded_passwords"] = decoded_for_llm
        intel["profile_data"] = profile.to_dict()
        intel["correlation_insights"] = analysis.correlation_data or []
        intel["derivation_chains"] = [c.to_dict() for c in analysis.derivation_chains]

        console.print("[dim]LLM: Generating targeted password candidates...[/dim]")
        try:
            llm_candidates = provider.generate_targeted_candidates(intel)
            if llm_candidates:
                console.print(
                    f"  [green]LLM contributed {len(llm_candidates)} targeted candidates.[/green]"
                )
            else:
                console.print("  [yellow]LLM returned no candidates — engine will use word pool only.[/yellow]")
        except Exception as exc:
            console.print(f"  [yellow]LLM candidate generation failed:[/] {exc}")

        console.print("[dim]LLM: Generating custom generation engine...[/dim]")
        try:
            raw_code = provider.generate_custom_code(intel)
            if raw_code:
                custom_code = _maybe_review_code(raw_code, provider, console)
                console.print("  [green]Custom generation engine ready.[/green]")
            else:
                console.print("  [yellow]LLM skipped code generation — using built-in engine.[/yellow]")
        except Exception as exc:
            console.print(f"  [yellow]LLM code generation failed:[/] {exc}")
            console.print("  [dim]Using built-in combinatorial engine.[/dim]")
    else:
        console.print(
            "[yellow]No LLM available — using combinatorial engine only. "
            "For better results, rerun with: --llm ollama[/yellow]"
        )

    # --- Preview & select ---
    tiers, llm_candidates = run_preview_session(
        tiers, llm_candidates, analysis, skip=skip_review,
    )

    cached_steps.append("targeted_candidates")
    write_target_folder(
        target_dir,
        profile,
        analysis,
        target_name=name,
        llm_model=llm_model,
        llm_candidates=llm_candidates,
        custom_code=custom_code,
        raw_text=raw_text,
        min_length=min_length,
        max_length=max_length,
        require_upper=require_upper,
        require_lower=require_lower,
        require_digit=require_digit,
        require_special=require_special,
        custom_specials=specials,
        cached_steps=cached_steps,
        leet_override=leet_override,
        leet_exhaustive=leet_exhaustive,
    )

    console.print(f"\n[bold green]Re-analysis complete.[/bold green] Script regenerated at:")
    console.print(f"  [cyan]{target_dir / 'generate_passwords.py'}[/cyan]")


@cli.command()
@click.option("-n", "--name", required=True, help="Target name")
def edit(name: str):
    """Open the target's profile.raw for editing.

    Opens the raw profile in your $EDITOR. After saving, run
    'xora analyze' to regenerate the password script.
    """
    target_dir = _target_dir(name)
    raw_path = target_dir / "profile.raw"
    if not raw_path.exists():
        console.print(f"[red]Error:[/] No profile found at [bold]{raw_path}[/bold]")
        console.print("Use [bold]xora add[/bold] to create a target first.")
        raise SystemExit(1)

    editor = os.environ.get("EDITOR", "vi")
    console.print(f"[dim]Opening {raw_path} in {editor}...[/dim]")
    subprocess.run([editor, str(raw_path)])

    console.print()
    console.print("[bold yellow]Profile updated.[/bold yellow]")
    console.print(f"Run [cyan]xora analyze -n {name}[/cyan] to regenerate the password script.")


@cli.command(name="list")
def list_targets():
    """List all target profiles in the current directory."""
    targets = sorted(XORA_DIR.glob("*-xora"))
    if not targets:
        console.print("[dim]No targets found. Use [bold]xora add[/bold] to create one.[/dim]")
        return

    table = Table(title="xora targets")
    table.add_column("Name", style="cyan bold")
    table.add_column("Folder", style="dim")
    table.add_column("Has Script", style="green")
    table.add_column("Words", justify="right")
    table.add_column("Passwords", justify="right")

    for t in targets:
        name = t.name.replace("-xora", "")
        has_script = "yes" if (t / "generate_passwords.py").exists() else "no"

        words = "-"
        passwords = "-"
        parsed = t / "profile.parsed.json"
        if parsed.exists():
            try:
                data = json.loads(parsed.read_text())
                all_words = []
                for key in ["nicknames", "pet_names", "interests", "teams",
                            "companies", "extra_words", "children_names"]:
                    all_words.extend(data.get(key, []))
                for val in [data.get("first_name", ""), data.get("last_name", ""),
                            data.get("partner_name", "")]:
                    if val:
                        all_words.append(val)
                words = str(len(all_words))
                passwords = str(len(data.get("known_passwords", [])))
            except (json.JSONDecodeError, KeyError):
                pass

        table.add_row(name, str(t), has_script, words, passwords)

    console.print(table)


@cli.command()
@click.option("-n", "--name", required=True, help="Target name")
def show(name: str):
    """Show the analysis report for a target."""
    target_dir = _target_dir(name)
    report_path = target_dir / "analysis.md"
    if not report_path.exists():
        console.print(f"[red]Error:[/] No analysis found for [bold]{name}[/bold]")
        raise SystemExit(1)

    console.print(report_path.read_text(encoding="utf-8"))


@cli.command()
@click.option("-n", "--name", required=True, help="Target name")
@click.confirmation_option(prompt="Are you sure you want to delete this target?")
def delete(name: str):
    """Delete a target profile and all its artifacts."""
    import shutil

    target_dir = _target_dir(name)
    if not target_dir.exists():
        console.print(f"[red]Error:[/] Target [bold]{name}[/bold] not found.")
        raise SystemExit(1)

    shutil.rmtree(target_dir)
    console.print(f"[bold red]Deleted:[/bold red] {target_dir}")


if __name__ == "__main__":
    cli()
