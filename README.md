# cfsniff

A good dog that sniffs out leaked secrets in files, directories, and text — powered by the [ClassiFinder](https://classifinder.ai) API.

## Install

```bash
pip install cfsniff
```

Clipboard support:

```bash
pip install "cfsniff[clipboard]"
```

## Quick Start

```bash
# 1. Install
pip install cfsniff

# 2. Set your API key (get one at https://classifinder.ai)
export CLASSIFINDER_API_KEY=cf_live_...

# 3. Sniff something
cfsniff audit
```

## Usage

**Scan a file**
```bash
cfsniff secrets.txt
```

**Scan a directory**
```bash
cfsniff ./src
```

**Pipe text in**
```bash
echo "token=ghp_abc123..." | cfsniff
```

**Scan your clipboard**
```bash
cfsniff --clipboard
```

**Audit current directory**
```bash
cfsniff audit
```

**Audit with extra paths**
```bash
cfsniff audit --include logs
```

**Audit and open an HTML report**
```bash
cfsniff audit --report report.html --open
```

## Output Formats

```bash
cfsniff audit                    # rich (default, color terminal output)
cfsniff audit --format plain     # plain text (CI-friendly)
cfsniff audit --format json      # machine-readable JSON
```

## HTML Reports

The `--report` flag writes a self-contained HTML file with a full findings summary — useful for sharing with teammates or attaching to tickets.

```bash
cfsniff audit --report report.html --open
```

## API Key

Get a free API key at **https://classifinder.ai**.

Set it via environment variable:

```bash
export CLASSIFINDER_API_KEY=cf_live_...
```

## License

MIT
