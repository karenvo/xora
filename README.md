# xora

Targeted password wordlist generator for red team engagements using AI.

xora takes a free-text profile describing a target and generates a **standalone Python script** that produces high-probability password candidates. The generated script has zero dependencies, runs anywhere Python 3 exists, and pipes directly into attack tools.

## Install

```bash
cd xora
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

On Kali Linux (or any system with an externally-managed Python environment), the venv step is required. After activating the venv, `xora` will be available for the rest of your session. To reactivate in a new shell: `source .venv/bin/activate`.

Alternatively, use `pipx` for a fully isolated install:

```bash
pipx install .
```

## Quick Start

```bash
# Create a target from a profile file
xora add -n john -f profile.txt

# View the analysis
xora show -n john

# Run the generated script
python3 john-xora/generate_passwords.py

# Pipe into attack tools
python3 john-xora/generate_passwords.py | hydra -l john -P /dev/stdin ssh://target
python3 john-xora/generate_passwords.py | hashcat -m 1000 hashes.txt
python3 john-xora/generate_passwords.py --format hydra --username john@corp.com
```

## Commands

| Command | Description |
|---|---|
| `xora add -n <name> -f <file>` | Create a target profile and generate a password script |
| `xora analyze -n <name>` | Re-analyze profile and regenerate the script |
| `xora edit -n <name>` | Edit the raw profile in your `$EDITOR` |
| `xora show -n <name>` | Display the analysis report |
| `xora list` | List all targets in the current directory |
| `xora delete -n <name>` | Delete a target and all artifacts |

## Interactive Review

After analysis completes, xora displays its findings and opens a review session before generating the password script. This lets you inspect the word pool, tweak leet behaviour, and set password policy based on what was actually found.

```
  Analysis Summary
  ┌─────────────────────────────────────────────┐
  │ Passwords: 23   Base words: 41   Numbers: 6 │
  └─────────────────────────────────────────────┘

  Word Pool        Tier      Words
  critical         Motley, Crue, ACDC, Ozzy, ...
  high             Guitar, Rock, Moon, Jungle, ...

  Incremental Password Chains Detected
    acdc123 → acdc1234 → acdc12345

  Leet Speak Usage  75%  ████████████████

  Review and refine before generating? [Y/n]:
```

During the session you can:

- **Add or remove words** from the pool inline (e.g. `+metallica -admin`)
- **Open the word pool in `$EDITOR`** for bulk edits
- **Request category suggestions** — xora asks the LLM for more words matching the detected themes
- **Set leet behaviour** — use historical rate, force on/off, set a custom percentage, or choose exhaustive mode (generates every substitution combination — requires a password policy)
- **Set password policy** — length range, required character classes, allowed specials

Skip the review entirely with `--yes` / `-y`:

```bash
xora analyze -n john --yes
xora add -n john -f profile.txt --yes
```

## LLM Enhancement (Optional)

Use a local or cloud LLM to deepen profile analysis and seed the generator with psychologically-targeted guesses.

```bash
# Local Ollama (auto-detected if running)
xora add -n john -f profile.txt --llm ollama/llama3.1:8b

# Anthropic Claude
XORA_API_KEY=sk-ant-... xora add -n john -f profile.txt --llm anthropic/claude-sonnet-4-20250514

# Any Ollama model
xora add -n john -f profile.txt --llm ollama/mistral

# Skip LLM entirely — rule-based only, no external calls
xora add -n john -f profile.txt --no-llm
```

If `--llm` is not specified, xora auto-detects the best available provider:
1. Local Ollama (if running) — nothing leaves the machine
2. Anthropic Claude (if `XORA_API_KEY` or `ANTHROPIC_API_KEY` is set)
3. Rule-based fallback (no LLM)

### What the LLM does

The LLM is used at analysis time only. The generated script is pure Python with zero LLM dependency.

When an LLM is available, it performs these tasks:

| Step | What the LLM does |
|---|---|
| Profile parsing | Extracts structured data (name, birthdate, interests, etc.) from free text |
| Password categorisation | Labels passwords by theme (music, family, dates, tech, …) |
| Semantic decomposition | Identifies the psychological meaning behind each password structure |
| Inference | Derives additional password-relevant facts from the profile context |
| Correlations | Cross-references passwords against profile fields to find anchors |
| Word curation | Selects the most password-relevant words from the full profile |
| **Targeted candidates** | **Generates 100–200 specific password guesses based on the target's psychology** |

The final step — targeted candidates — is the key one. The LLM returns a **JSON list of password strings** (e.g. `["MotleyCrue1983!", "m0tl3y_cr3w!"]`), not Python code. These are injected into `LLM_CANDIDATES` in the generated script and rise to the top of the ranked output because xora's engine seeds them first.

xora's own combinatorial engine (leet expansion, case variants, separator combos, derivation chain predictions) handles all generation logic — no LLM-written code is ever executed. This keeps the generated script reliable regardless of which model was used.

### Input Type Flags

By default, xora auto-detects whether the input is a password list or a profile. You can override this explicitly:

```bash
# Input is a plain list of passwords — skips profile parsing, inference, and semantics
xora add -n target -f passwords.txt --passwords

# Input is a profile/OSINT file — forces full profile parsing even if it looks like passwords
xora add -n target -f profile.txt --profile-file

# Same flags work on analyze
xora analyze -n target --passwords
xora analyze -n target --profile-file
```

When the input is a password list (auto-detected or via `--passwords`), xora skips inference and semantic decomposition — those steps require personal context to be meaningful. Categorization and pattern analysis still run.

## Password Policy

Set the target org's password requirements at generation time. These get baked into the generated script so only valid candidates are produced.

```bash
# Require 12+ chars with uppercase, digit, and special character
xora add -n john -f profile.txt --min-length 12 --require-upper --require-digit --require-special

# Only use specific special characters (e.g. target system only allows these)
xora add -n john -f profile.txt --specials '!@#$'

# Combine policy + custom specials
xora add -n john -f profile.txt --min-length 10 --require-special --specials '!@#$%^&*'

# Re-analyze with updated policy
xora analyze -n john --min-length 10 --require-special --specials '!@#'
```

| Flag | Default | Description |
|---|---|---|
| `--min-length` | 8 | Minimum password length |
| `--max-length` | 64 | Maximum password length |
| `--require-upper` | off | Require at least one uppercase letter |
| `--require-lower` | off | Require at least one lowercase letter |
| `--require-digit` | off | Require at least one digit |
| `--require-special` | off | Require at least one special character |
| `--specials` | auto | Custom special characters to use (e.g. `'!@#$%^&*'`) |

By default, special characters are auto-detected from known passwords. If none are found, xora uses `!@#$%1`. Use `--specials` to restrict to only the characters the target system allows.

The generated script also supports runtime overrides (e.g. `python3 generate_passwords.py --min-length 14 --require-special`).

## Re-Analysis Options

```bash
# Re-analyze with a different LLM
xora analyze -n john --llm ollama/mistral

# Force full re-analysis, ignoring cached results
xora analyze -n john --no-cache

# Re-analyze without LLM
xora analyze -n john --no-llm
```

Results from expensive LLM steps are cached per-target. Cached steps are skipped on subsequent runs unless `--no-cache` is passed or the profile changes.

## Generated Script Usage

```bash
python3 <name>-xora/generate_passwords.py                    # all candidates to stdout
python3 <name>-xora/generate_passwords.py --ranked           # sorted by likelihood
python3 <name>-xora/generate_passwords.py --limit 500        # cap output
python3 <name>-xora/generate_passwords.py --format hydra     # user:password pairs
python3 <name>-xora/generate_passwords.py --format burp      # deduplicated, one per line
python3 <name>-xora/generate_passwords.py --format credstuff # email:password pairs
python3 <name>-xora/generate_passwords.py -o wordlist.txt    # write to file
python3 <name>-xora/generate_passwords.py --min-length 12    # override policy
```

## Profile Format

Profiles are free-text files. xora works with both structured and unstructured input:

```
# Personal
Name: Jane Doe
Birthday: 1992-07-04
Nickname: JD

# Pets
Dog: Bella

# Interests
yoga, hiking, coffee

# Known Passwords
Bella2019!
Yoga#92
```

You can also pass a plain list of known passwords with no profile fields. xora detects this automatically and runs a focused analysis (pattern detection, categorization, strength assessment) without inference steps that require personal context.

## Target Folder Structure

```
<name>-xora/
├── profile.raw             # Original input file
├── profile.parsed.json     # Structured data extracted from profile
├── analysis.json           # Full pattern and semantic analysis data
├── analysis.md             # Human-readable report
├── cache_meta.json         # Tracks which LLM steps have been cached
└── generate_passwords.py   # Standalone password generator (the main artifact)
```
