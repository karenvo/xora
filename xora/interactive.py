"""Interactive review session between analysis and code generation.

After analysis completes, xora displays findings and opens a guided
conversation letting the user refine the word pool, set password policy,
and decide how generation should behave before the script is written.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
