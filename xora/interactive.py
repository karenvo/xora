"""Interactive review session between analysis and code generation.

After analysis completes, xora displays findings and opens a guided
conversation letting the user refine the word pool, set password policy,
and decide how generation should behave before the script is written.
"""

from __future__ import annotations

import itertools
import os
import subprocess
import tempfile
from pathlib import Path

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


# =========================================================================
# DISPLAY HELPERS
# =========================================================================

def _display_word_tiers(tiers: dict[str, list[str]]) -> None:
    table = Table(title="Word Pool", show_header=True, header_style="bold cyan")
    table.add_column("Tier", style="bold")
    table.add_column("Words")
    for tier, words in tiers.items():
        if words:
            table.add_row(
                tier,
                ", ".join(words[:20]) + (f"  (+{len(words) - 20} more)" if len(words) > 20 else ""),
            )
    console.print(table)


def _display_patterns(analysis) -> None:
    if not analysis.patterns:
        return
    console.print("\n[bold]Detected Patterns[/bold]")
    for pat in analysis.patterns[:10]:
        console.print(f"  [cyan]{pat.source}[/cyan] → [dim]{pat.template}[/dim]")


def _display_semantics(analysis) -> None:
    sem = getattr(analysis, "semantic_analysis", None)
    if not sem:
        return
    pws = getattr(sem, "passwords", [])
    if not pws:
        return
    console.print("\n[bold]Semantic Decomposition[/bold]")
    for sp in pws[:8]:
        tmpl = sp.semantic_template or "unknown"
        parts = " + ".join(
            f"[yellow]{c.role}[/yellow]:[cyan]{c.value}[/cyan]"
            for c in sp.components
        )
        console.print(f"  {sp.original!r} → {parts}")
        console.print(f"    [dim]template: {tmpl}  category: {sp.category}[/dim]")
    if len(pws) > 8:
        console.print(f"  [dim]… and {len(pws) - 8} more[/dim]")


def _display_leet(profile) -> None:
    pws = profile.known_passwords
    if not pws:
        return
    leet_chars = set("0134578@$!|+(€¡")
    leet_count = sum(1 for pw in pws if any(c in leet_chars for c in pw))
    pct = leet_count / len(pws) if pws else 0
    bar = "█" * int(pct * 20)
    console.print(
        f"\n[bold]Leet Speak Usage[/bold]  {pct:.0%}  [green]{bar}[/green]  "
        f"({leet_count}/{len(pws)} passwords)"
    )


_CHAIN_TYPE_LABEL = {
    "policy_ratchet": "Policy Ratchet",
    "sequential_enum": "Sequential Enumeration",
}

_CHAIN_TYPE_DESC = {
    "policy_ratchet": "user added complexity one class at a time",
    "sequential_enum": "user cycled through accounts/resets with an incrementing counter",
}


def _display_derivation_chains(profile, analysis=None) -> None:
    """Show derivation chains pre-computed by pattern_analyzer."""
    chains = getattr(analysis, "derivation_chains", []) if analysis else []
    if not chains:
        return

    console.print("\n[bold yellow]Derivation Chains Detected[/bold yellow]")
    for chain in chains[:8]:
        label = _CHAIN_TYPE_LABEL.get(chain.chain_type, chain.chain_type)
        desc = _CHAIN_TYPE_DESC.get(chain.chain_type, "")
        member_str = " → ".join(f"[cyan]{p}[/cyan]" for p in chain.members)
        console.print(f"  [bold]{label}[/bold]  ({desc})")
        console.print(f"    {member_str}")
        if chain.next_likely:
            next_str = ", ".join(f"[green]{p}[/green]" for p in chain.next_likely[:5])
            console.print(f"    [dim]→ likely next:[/dim] {next_str}")
    if len(chains) > 8:
        console.print(f"  [dim]… and {len(chains) - 8} more chains[/dim]")
    console.print(
        "  [dim]next_likely candidates are seeded at the top of generation.[/dim]"
    )


def _display_categories(analysis) -> None:
    pw_profile = getattr(analysis, "password_profile", None)
    if not pw_profile:
        return
    dist = getattr(pw_profile, "category_distribution", {}) or {}
    if not dist:
        return
    console.print("\n[bold]Password Themes[/bold]")
    for cat, pct in sorted(dist.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * int(pct / 100 * 20)
        console.print(f"  {cat:<16} {pct:5.1f}%  [green]{bar}[/green]")


def _display_summary(profile, analysis, tiers: dict[str, list[str]]) -> None:
    """Print the full analysis summary before asking questions."""
    pws = profile.known_passwords
    words = profile.all_base_words()

    console.print(Panel(
        f"[bold]Passwords[/bold]: {len(pws)}   "
        f"[bold]Base words[/bold]: {len(words)}   "
        f"[bold]Numbers[/bold]: {len(profile.all_numbers())}",
        title="[bold cyan]Analysis Summary[/bold cyan]",
    ))

    _display_word_tiers(tiers)
    _display_patterns(analysis)
    _display_derivation_chains(profile, analysis)
    _display_semantics(analysis)
    _display_leet(profile)
    _display_categories(analysis)


# =========================================================================
# WORD POOL EDITOR
# =========================================================================

def _edit_word_pool_inline(profile) -> None:
    """Let the user add/remove words interactively."""
    console.print("\n[bold]Current word pool[/bold] (space-separated):")
    words = profile.all_base_words()
    console.print("  " + " ".join(words) if words else "  (empty)")
    console.print()
    console.print("[dim]Commands:[/dim]")
    console.print("  [cyan]+word1 word2[/cyan]  — add words")
    console.print("  [cyan]-word1 word2[/cyan]  — remove words")
    console.print("  [cyan]done[/cyan]           — finish editing")
    console.print()

    while True:
        raw = console.input("[bold]word pool>[/bold] ").strip()
        if not raw or raw.lower() == "done":
            break
        if raw.startswith("+"):
            to_add = raw[1:].split()
            added = []
            for w in to_add:
                if w and w not in profile.extra_words:
                    profile.extra_words.append(w)
                    added.append(w)
            if added:
                console.print(f"  [green]Added:[/green] {', '.join(added)}")
        elif raw.startswith("-"):
            to_remove = set(raw[1:].split())
            removed = []
            for lst_name in ["extra_words", "interests", "nicknames", "pet_names",
                             "teams", "companies", "children_names"]:
                lst = getattr(profile, lst_name, [])
                before = len(lst)
                lst[:] = [w for w in lst if w not in to_remove]
                removed += [w for w in to_remove if len(lst) < before]
            if removed:
                console.print(f"  [yellow]Removed:[/yellow] {', '.join(set(removed))}")
            else:
                console.print("  [dim]No matching words found.[/dim]")
        else:
            console.print("  [dim]Start with + to add or - to remove.[/dim]")


def _edit_word_pool_in_editor(profile, target_dir: Path) -> None:
    """Open a temp file in $EDITOR listing the current word pool."""
    words = profile.all_base_words()
    content = "\n".join([
        "# xora word pool editor",
        "# Add or remove words — one per line.",
        "# Lines starting with # are ignored.",
        "",
    ] + words)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        tmp = f.name

    editor = os.environ.get("EDITOR", "vi")
    subprocess.run([editor, tmp])

    new_words = []
    with open(tmp, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                new_words.append(line)
    Path(tmp).unlink(missing_ok=True)

    # Replace extra_words with the edited list (other profile lists stay)
    profile.extra_words = new_words
    console.print(f"  [green]Word pool updated:[/green] {len(new_words)} words")


# =========================================================================
# POLICY QUESTIONS
# =========================================================================

def _ask_policy(
    min_length: int,
    max_length: int,
    require_upper: bool,
    require_lower: bool,
    require_digit: bool,
    require_special: bool,
    specials: str | None,
) -> dict:
    """Ask the user if they want to set / update password policy."""
    console.print("\n[bold]Password Policy[/bold]")
    console.print(
        f"  Current: length {min_length}–{max_length}"
        + (", upper" if require_upper else "")
        + (", lower" if require_lower else "")
        + (", digit" if require_digit else "")
        + (", special" if require_special else "")
        + (f", specials: {specials}" if specials else "")
    )
    console.print(
        "  [dim]Do you know the target service's password policy? "
        "Setting this produces a tighter wordlist. (Enter to skip)[/dim]"
    )

    raw = console.input("  Min length [{}]: ".format(min_length)).strip()
    if raw.isdigit():
        min_length = int(raw)

    raw = console.input("  Max length [{}]: ".format(max_length)).strip()
    if raw.isdigit():
        max_length = int(raw)

    def _yesno(prompt: str, current: bool) -> bool:
        default = "Y" if current else "n"
        raw = console.input(f"  {prompt} [{default}]: ").strip().lower()
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        return current

    require_upper = _yesno("Require uppercase?", require_upper)
    require_lower = _yesno("Require lowercase?", require_lower)
    require_digit = _yesno("Require digit?", require_digit)
    require_special = _yesno("Require special character?", require_special)

    raw = console.input(
        f"  Allowed specials [{specials or 'auto'}]: "
    ).strip()
    if raw and raw != "auto":
        specials = raw

    return {
        "min_length": min_length,
        "max_length": max_length,
        "require_upper": require_upper,
        "require_lower": require_lower,
        "require_digit": require_digit,
        "require_special": require_special,
        "specials": specials,
    }


# =========================================================================
# LEET QUESTION
# =========================================================================

def _ask_leet(profile) -> tuple[float | None, bool]:
    """Ask how leet speak should be handled.

    Returns (leet_pct_override, leet_exhaustive).
    leet_pct_override is None to keep historical rate.
    leet_exhaustive=True generates every possible substitution combination.
    """
    pws = profile.known_passwords
    if not pws:
        return None, False

    leet_chars = set("0134578@$!|+(€¡")
    leet_count = sum(1 for pw in pws if any(c in leet_chars for c in pw))
    historical_pct = leet_count / len(pws)

    console.print(f"\n[bold]Leet Speak[/bold]  (historical usage: {historical_pct:.0%})")
    console.print("  [1] Use historical rate ({:.0%})".format(historical_pct))
    console.print("  [2] Force leet on all words (100%)")
    console.print("  [3] No leet (plain words only)")
    console.print("  [4] Custom percentage")
    console.print("  [5] Exhaustive — every substitution combination")
    console.print("      [dim](warning: output grows exponentially with word length)[/dim]")
    console.print("  [Enter] Keep historical")

    choice = console.input("  Choice: ").strip()
    if choice == "1" or choice == "":
        return None, False
    if choice == "2":
        return 1.0, False
    if choice == "3":
        return 0.0, False
    if choice == "4":
        raw = console.input("  Enter leet % (0–100): ").strip()
        try:
            return min(1.0, max(0.0, int(raw) / 100)), False
        except ValueError:
            return None, False
    if choice == "5":
        console.print(
            "\n  [bold yellow]Exhaustive mode[/bold yellow] generates every possible leet "
            "substitution combination per word.\n"
            "  Output can be very large — a password policy is [bold]required[/bold] to keep it useful.\n"
        )
        return 1.0, True
    return None, False


# =========================================================================
# MAIN REVIEW SESSION
# =========================================================================

def run_review_session(
    profile,
    analysis,
    tiers: dict[str, list[str]],
    target_dir: Path,
    *,
    min_length: int = 8,
    max_length: int = 64,
    require_upper: bool = False,
    require_lower: bool = False,
    require_digit: bool = False,
    require_special: bool = False,
    specials: str | None = None,
    provider=None,
) -> dict:
    """Run the interactive review session.

    Displays analysis findings and guides the user through refinements.
    Returns a dict of generation parameters (policy overrides, leet override, etc.)
    that the caller should pass to codegen.
    """
    _display_summary(profile, analysis, tiers)

    console.print()
    skip = console.input(
        "[bold]Review and refine before generating?[/bold] [Y/n]: "
    ).strip().lower()

    result: dict = {
        "min_length": min_length,
        "max_length": max_length,
        "require_upper": require_upper,
        "require_lower": require_lower,
        "require_digit": require_digit,
        "require_special": require_special,
        "specials": specials,
        "leet_override": None,
        "leet_exhaustive": False,
    }

    if skip in ("n", "no"):
        return result

    # --- Word pool ---
    console.print("\n[bold cyan]Step 1 — Word Pool[/bold cyan]")
    wp_choice = console.input(
        "  [1] Edit inline  [2] Open in $EDITOR  [Enter] Skip: "
    ).strip()
    if wp_choice == "1":
        _edit_word_pool_inline(profile)
    elif wp_choice == "2":
        _edit_word_pool_in_editor(profile, target_dir)

    # --- Category word suggestions ---
    if provider:
        sem = getattr(analysis, "semantic_analysis", None)
        cats = set()
        if sem:
            for sp in getattr(sem, "passwords", []):
                if sp.category and sp.category not in ("unknown", "mixed"):
                    cats.add(sp.category)

        if cats:
            console.print(f"\n[bold cyan]Step 2 — Category Suggestions[/bold cyan]")
            console.print(
                f"  Primary themes detected: [yellow]{', '.join(sorted(cats))}[/yellow]"
            )
            want_suggest = console.input(
                "  Want more words suggested for these themes? [y/N]: "
            ).strip().lower()
            if want_suggest in ("y", "yes"):
                console.print("  [dim]Asking LLM for category-related words...[/dim]")
                try:
                    from xora.llm.base import INFERENCE_PROMPT
                    theme_prompt = (
                        f"The target's passwords are themed around: {', '.join(sorted(cats))}.\n"
                        f"Suggest 15 additional single words closely related to these themes "
                        f"that someone might use in a password. Return only a JSON array of strings."
                    )
                    raw = provider.generate_text(theme_prompt, max_tokens=512)
                    import json, re
                    m = re.search(r"\[.*?\]", raw, re.DOTALL)
                    if m:
                        suggestions = json.loads(m.group(0))
                        added = []
                        for w in suggestions:
                            if isinstance(w, str) and w and w not in profile.extra_words:
                                profile.extra_words.append(w)
                                added.append(w)
                        if added:
                            console.print(f"  [green]Added {len(added)} suggested words:[/green] {', '.join(added)}")
                except Exception as exc:
                    console.print(f"  [yellow]Suggestion failed:[/] {exc}")

    # --- Leet ---
    console.print(f"\n[bold cyan]Step 3 — Leet Speak[/bold cyan]")
    leet_override, leet_exhaustive = _ask_leet(profile)
    if leet_override is not None:
        result["leet_override"] = leet_override
        console.print(f"  [green]Leet override set to {leet_override:.0%}[/green]")
    result["leet_exhaustive"] = leet_exhaustive

    # --- Policy ---
    console.print(f"\n[bold cyan]Step 4 — Password Policy[/bold cyan]")
    if leet_exhaustive:
        console.print(
            "  [bold yellow]Exhaustive leet mode is on — policy is required.[/bold yellow]\n"
            "  Without a policy the output will be enormous. Set at minimum a length range\n"
            "  and at least one character class requirement.\n"
        )
    policy = _ask_policy(
        min_length, max_length,
        require_upper, require_lower, require_digit, require_special, specials,
    )
    result.update(policy)

    # Enforce: exhaustive mode must have at least one policy constraint
    if leet_exhaustive:
        has_constraint = (
            policy["min_length"] > 8
            or policy["max_length"] < 64
            or policy["require_upper"]
            or policy["require_lower"]
            or policy["require_digit"]
            or policy["require_special"]
            or policy["specials"]
        )
        if not has_constraint:
            console.print(
                "\n  [red]No policy set.[/red] Exhaustive mode without a policy would generate "
                "an extremely large wordlist.\n"
                "  Defaulting to: min-length 8, require-digit, require-special.\n"
            )
            result["require_digit"] = True
            result["require_special"] = True

    console.print()
    console.print("[bold green]Review complete.[/bold green] Proceeding to generate...")
    return result


# =========================================================================
# PREVIEW & SELECT SESSION
# =========================================================================

def _score_word(word: str, tier: str, analysis) -> float:
    """Return a rough probability score (0–1) for a word."""
    base = {"critical": 0.92, "high": 0.72, "medium": 0.48, "low": 0.28}.get(tier, 0.3)
    # Boost if word appears in known passwords
    kp_lower = [p.lower() for p in getattr(analysis, "known_passwords", [])]
    hits = sum(1 for p in kp_lower if word.lower() in p)
    boost = min(hits * 0.04, 0.08)
    return min(base + boost, 0.99)


def _base_combos(
    tiers: dict[str, list[str]],
    llm_candidates: list[str],
    analysis,
    limit: int = 40,
) -> list[tuple[float, str, str]]:
    """Generate representative (score, base_form, source) triples.

    base_form is always lower-case so the user sees the raw concept
    before case/leet/separator expansion.
    """
    seen: set[str] = set()
    results: list[tuple[float, str, str]] = []

    def _add(score: float, raw: str, source: str) -> None:
        key = raw.lower()
        if key in seen or not raw.strip():
            return
        seen.add(key)
        results.append((score, key, source))

    # Derivation chain predictions (highest confidence)
    for chain in getattr(analysis, "derivation_chains", []):
        for pw in chain.get("next_likely", []):
            _add(0.97, pw, "derivation prediction")

    # LLM-suggested specific passwords
    for pw in (llm_candidates or [])[:30]:
        _add(0.88, pw, "LLM targeted guess")

    # Known passwords themselves as anchors
    for pw in getattr(analysis, "known_passwords", [])[:10]:
        _add(0.85, pw, "known password")

    # Word × number suffix combos (critical tier)
    for word in tiers.get("critical", [])[:12]:
        score = _score_word(word, "critical", analysis)
        _add(score, word, "critical word")
        for num in ["1", "2", "123", "1234", "2024", "2025"]:
            _add(score - 0.05, f"{word}{num}", "word+number")

    # Two-word combos (critical × high)
    crit = tiers.get("critical", [])[:6]
    high = tiers.get("high", [])[:6]
    for w1, w2 in itertools.permutations(crit + high, 2):
        score = _score_word(w1, "critical", analysis) * 0.85
        _add(score, f"{w1}{w2}", "two-word combo")
        if len(results) >= limit * 2:
            break

    # High tier single words
    for word in high:
        score = _score_word(word, "high", analysis)
        _add(score, word, "high word")

    results.sort(key=lambda x: x[0], reverse=True)
    return results[:limit]


def _display_preview(
    combos: list[tuple[float, str, str]],
    tiers: dict[str, list[str]],
    analysis,
) -> None:
    """Render the ranked preview table."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]Password Preview[/bold cyan]\n"
        "[dim]Ranked candidates shown in base form (lower-case).\n"
        "Generation will expand each with case variants, leet, separators, and numbers.[/dim]",
        border_style="cyan",
    ))
    console.print()

    # --- Word tiers summary ---
    tier_table = Table(title="Word Pool", show_header=True, header_style="bold", box=None)
    tier_table.add_column("Tier", style="bold", width=10)
    tier_table.add_column("Words", style="cyan")
    tier_table.add_column("Count", justify="right", style="dim")
    for tier, color in [("critical", "green"), ("high", "yellow"), ("medium", "white"), ("low", "dim")]:
        words = tiers.get(tier, [])
        if words:
            tier_table.add_row(
                f"[{color}]{tier}[/{color}]",
                ", ".join(words[:12]) + (" …" if len(words) > 12 else ""),
                str(len(words)),
            )
    console.print(tier_table)
    console.print()

    # --- Pattern templates ---
    templates = getattr(analysis, "pattern_templates", [])[:8]
    if templates:
        t2 = Table(title="Observed Structural Patterns", show_header=True, header_style="bold", box=None)
        t2.add_column("#", justify="right", style="dim", width=3)
        t2.add_column("Template", style="yellow")
        for i, tmpl in enumerate(templates, 1):
            t2.add_row(str(i), tmpl)
        console.print(t2)
        console.print()

    # --- Ranked candidate preview ---
    prev_table = Table(
        title="Top Candidate Bases (all lower-case → will be expanded)",
        show_header=True,
        header_style="bold",
        box=None,
    )
    prev_table.add_column("#", justify="right", style="dim", width=3)
    prev_table.add_column("Base form", style="bold cyan")
    prev_table.add_column("Source", style="dim")
    prev_table.add_column("Probability", justify="right")

    bands = [
        ("Very high", 0.90, "green"),
        ("High",      0.75, "yellow"),
        ("Medium",    0.55, "white"),
        ("Lower",     0.00, "dim"),
    ]
    last_band = ""
    for idx, (score, base, source) in enumerate(combos, 1):
        band_label, band_color = "", "white"
        for label, threshold, color in bands:
            if score >= threshold:
                band_label, band_color = label, color
                break
        if band_label != last_band:
            prev_table.add_row("", f"[{band_color}]── {band_label} confidence ──[/{band_color}]", "", "")
            last_band = band_label
        prev_table.add_row(
            str(idx),
            base,
            source,
            f"[{band_color}]{score:.0%}[/{band_color}]",
        )

    console.print(prev_table)


def run_preview_session(
    tiers: dict[str, list[str]],
    llm_candidates: list[str] | None,
    analysis,
    *,
    skip: bool = False,
) -> tuple[dict[str, list[str]], list[str]]:
    """Show a ranked preview of candidates and let the user narrow the selection.

    Returns a (filtered_tiers, filtered_llm_candidates) tuple. If the user
    accepts all or ``skip`` is True, the originals are returned unchanged.
    """
    llm_candidates = llm_candidates or []
    combos = _base_combos(tiers, llm_candidates, analysis, limit=40)

    if skip:
        return tiers, llm_candidates

    _display_preview(combos, tiers, analysis)

    console.print(
        "\n[bold]Select which candidates to include in generation:[/bold]\n"
        "  [cyan]a[/cyan]       — keep all (full generation run)\n"
        "  [cyan]1 3 5[/cyan]   — include only those numbered candidates as seeds\n"
        "  [cyan]1-10[/cyan]    — include a range\n"
        "  [cyan]top5[/cyan]    — shorthand for the top 5\n"
    )

    raw = console.input("[bold cyan]> [/bold cyan]").strip().lower()

    if not raw or raw in ("a", "all", ""):
        console.print("[dim]Keeping full candidate set.[/dim]")
        return tiers, llm_candidates

    # Parse top-N shorthand
    import re as _re
    top_match = _re.fullmatch(r"top(\d+)", raw)
    if top_match:
        raw = " ".join(str(i) for i in range(1, int(top_match.group(1)) + 1))

    # Parse individual numbers and ranges
    selected_indices: set[int] = set()
    for token in _re.split(r"[\s,]+", raw):
        range_match = _re.fullmatch(r"(\d+)-(\d+)", token)
        if range_match:
            lo, hi = int(range_match.group(1)), int(range_match.group(2))
            selected_indices.update(range(lo, hi + 1))
        elif token.isdigit():
            selected_indices.add(int(token))

    if not selected_indices:
        console.print("[dim]Could not parse selection — keeping full candidate set.[/dim]")
        return tiers, llm_candidates

    selected_combos = [
        combos[i - 1] for i in sorted(selected_indices)
        if 1 <= i <= len(combos)
    ]
    if not selected_combos:
        console.print("[dim]No valid selections — keeping full candidate set.[/dim]")
        return tiers, llm_candidates

    selected_bases = {base for _, base, _ in selected_combos}
    console.print(
        f"  [green]Selected {len(selected_bases)} base candidates.[/green] "
        "Generation will expand these with all configured variants."
    )

    # Filter LLM candidates to only those whose base matches a selection
    filtered_llm = [
        pw for pw in llm_candidates
        if pw.lower() in selected_bases
        or any(pw.lower().startswith(b) or b in pw.lower() for b in selected_bases)
    ]

    # Filter word tiers to only words that appear in selections
    filtered_tiers: dict[str, list[str]] = {}
    for tier, words in tiers.items():
        kept = [w for w in words if w.lower() in selected_bases]
        # Always keep at least the first critical word so generation is never empty
        if not kept and tier == "critical" and tiers.get("critical"):
            kept = tiers["critical"][:3]
        filtered_tiers[tier] = kept

    # Inject any selected bases that aren't in the tiers as extra critical words
    all_tier_words_lower = {
        w.lower() for ws in filtered_tiers.values() for w in ws
    }
    extras = [
        base.capitalize() for _, base, _ in selected_combos
        if base not in all_tier_words_lower and " " not in base
    ]
    if extras:
        filtered_tiers.setdefault("critical", []).extend(extras)

    return filtered_tiers, filtered_llm
