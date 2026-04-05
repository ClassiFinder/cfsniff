# Getting Started with cfsniff

cfsniff is a command-line tool that scans your machine for leaked secrets — API keys, tokens, passwords, and credentials hiding in places you've probably forgotten about: shell history, config files, environment variables, cloud credentials.

It's not a git scanner. Tools like TruffleHog and Gitleaks already cover your repositories. cfsniff covers everything else.

---

## How it works

1. cfsniff reads files on your local machine (shell history, dotfiles, configs, etc.)
2. The text is sent to the [ClassiFinder](https://classifinder.ai) API for scanning
3. Findings are printed to your terminal (or saved as an HTML report)
4. Nothing is stored — not by cfsniff, not by the API

cfsniff is stateless. It doesn't log, cache, or persist anything. The API processes your text in memory and discards it after responding. The scanner engine is [open source](https://github.com/classifinder) so you can verify this yourself.

---

## Install

```bash
pipx install cfsniff
```

Or with pip: `pip install cfsniff`

Requires Python 3.9+.

---

## Get an API key

cfsniff uses the ClassiFinder API to scan text. You'll need a free API key:

1. Go to [classifinder.ai](https://classifinder.ai)
2. Request an API key (it's free)
3. Set it in your shell:

```bash
export CLASSIFINDER_API_KEY=ss_live_your_key_here
```

Add this to your `~/.zshrc` or `~/.bashrc` to make it persistent.

---

## Run your first audit

```bash
cfsniff audit
```

This scans well-known locations on your machine where secrets tend to accumulate:

| Category | What it checks |
|----------|---------------|
| Shell history | `~/.zsh_history`, `~/.bash_history` |
| Shell config | `~/.zshrc`, `~/.bashrc`, `~/.profile` |
| Environment files | `.env` files in home, Desktop, Documents, Downloads |
| Cloud credentials | `~/.aws/credentials`, `~/.azure/credentials`, GCP application credentials |
| Package managers | `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials` |
| Containers | `~/.docker/config.json`, `~/.kube/config` |
| SSH | `~/.ssh/config` |

Missing files are silently skipped — most people won't have all of these.

To also scan log files (macOS `~/Library/Logs`, Linux `/var/log`):

```bash
cfsniff audit --include logs
```

---

## Read the output

cfsniff prints findings grouped by file:

```
~/.zsh_history
  line 428    | Stripe Live Secret Key | critical | 0.99 | sk_l****p7dc
  line 444    | AWS Access Key ID      | critical | 0.99 | AKIA****3284
  line 492    | Anthropic API Key      | critical | 0.99 | sk-a****u901

~/.pypirc
  line 3      | PyPI API Token         | critical | 0.99 | pypi****yeZA
```

Each finding shows:
- **Line number** — where in the file the secret was found
- **Type** — what kind of secret (AWS key, Stripe key, JWT, etc.)
- **Severity** — `critical`, `high`, `medium`, or `low`
- **Confidence** — how sure the scanner is (0.0 to 1.0)
- **Preview** — a masked version of the value (first 4 + last 4 characters)

Secret values are never shown in full. The API returns masked previews only — this is a security feature, not a limitation.

---

## Generate an HTML report

```bash
cfsniff audit --report report.html
```

This creates a self-contained HTML file you can open in any browser — no server needed. Useful for sharing with your team or attaching to a security review.

To open it immediately:

```bash
cfsniff audit --report report.html --open
```

---

## Scan specific files

cfsniff isn't just for audit mode. You can point it at anything:

```bash
# Scan a single file
cfsniff .env.local

# Scan a directory (recursive)
cfsniff ~/Downloads/exported-chats/

# Scan piped text
cat chatgpt-export.json | cfsniff

# Scan your clipboard
pip install "cfsniff[clipboard]"
cfsniff --clipboard
```

This is useful for checking data exports (ChatGPT conversations, Slack exports, Notion dumps), log files, or anything you're about to share with someone.

---

## Filter results

Too noisy? Narrow it down:

```bash
# Only show high and critical severity
cfsniff audit --min-severity high

# Only show findings with 90%+ confidence
cfsniff audit --min-confidence 0.9
```

---

## Machine-readable output

For scripts and CI:

```bash
# Plain text (one finding per line, colon-delimited)
cfsniff audit --format plain

# JSON
cfsniff audit --format json
```

cfsniff exits with code `2` when secrets are found, `0` when clean, and `1` on errors. This means you can use it in scripts:

```bash
cfsniff audit --format plain --min-severity high || echo "secrets found!"
```

---

## What it detects

cfsniff uses ClassiFinder's scanner engine, which recognizes 88 types of secrets across these categories:

- **Cloud providers** — AWS, GCP, Azure access keys and secrets
- **Payment** — Stripe, PayPal, Square API keys; credit card numbers
- **AI/ML** — OpenAI, Anthropic, Cohere, HuggingFace, Replicate, Groq API keys
- **Version control** — GitHub PATs (classic and fine-grained), GitLab tokens
- **Communication** — Slack, Discord, Twilio, SendGrid tokens
- **Databases** — PostgreSQL, MySQL, MongoDB, Redis connection strings
- **Generic** — JWTs, bearer tokens, PEM private keys, high-entropy strings in env vars

The full pattern list is at [classifinder.ai](https://classifinder.ai).

---

## Privacy and trust

This matters because cfsniff reads sensitive files. Here's the deal:

- **cfsniff is open source (MIT).** Read the code. It's a thin CLI that reads files and calls an API. No telemetry, no analytics, no phone-home.
- **The ClassiFinder API is stateless.** Text is processed in memory and discarded after the response. No database of scanned text exists. The scanner engine is also [open source](https://github.com/classifinder) so you can audit exactly what happens to your data.
- **Secret values are never returned in full.** The API masks values to first 4 + last 4 characters. Even if the response were intercepted, full secrets wouldn't be exposed.
- **All communication is over HTTPS.**

If you're not comfortable sending text to an external API, that's a valid position. The open-source scanner engine can be used directly for fully offline scanning — cfsniff itself is designed for convenience over that engine.

---

## What to do when you find secrets

1. **Rotate the credential immediately.** Go to the provider's dashboard (AWS Console, Stripe Dashboard, GitHub Settings, etc.) and generate a new key. Revoke the old one.
2. **Clean the source.** For shell history: `history -c` or edit the file directly. For config files: replace with environment variable references.
3. **Check for damage.** If the secret was in shell history, it was probably typed interactively — check if it was also committed to a repo or shared elsewhere.
4. **Prevent recurrence.** Don't type secrets into the terminal. Use a secrets manager, `.env` files (that are `.gitignore`d), or your shell's built-in secret input.

---

## Uninstall

```bash
pip uninstall cfsniff
```

cfsniff doesn't create any files or directories on your system (besides the HTML report, if you asked for one). Nothing to clean up.
