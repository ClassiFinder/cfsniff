# cfsniff

[![PyPI version](https://img.shields.io/pypi/v/cfsniff.svg)](https://pypi.org/project/cfsniff/) [![Python versions](https://img.shields.io/pypi/pyversions/cfsniff.svg)](https://pypi.org/project/cfsniff/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

[![Provenance: PyPI Trusted Publishing](https://img.shields.io/badge/provenance-PyPI%20trusted%20publishing%20%2B%20PEP%20740-brightgreen.svg)](https://pypi.org/project/cfsniff/)

A good dog that sniffs out leaked secrets in files, directories, and text — powered by the [ClassiFinder](https://classifinder.ai) API.

## Install

```bash
pipx install cfsniff
```

Or with pip:

```bash
pip install cfsniff
```

## Quick Start

```bash
# 1. Install
pipx install cfsniff

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

## Verifying This Build

Every release is published via [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) with [PEP 740 build attestations](https://docs.pypi.org/attestations/). No long-lived API tokens. The wheel you `pip install` is byte-identical to what GitHub Actions built from a tagged commit.

To verify a release: visit the [project page on PyPI](https://pypi.org/project/cfsniff/), click **Download files**, and check the **Provenance** section under each artifact. You'll see the sigstore attestation, the GitHub workflow run, and the exact commit SHA — all logged to the public [Sigstore transparency log](https://search.sigstore.dev/) for independent verification.

This answers "is the wheel what's in the source?" — the cryptographic chain proves this wheel was built from `ClassiFinder/cfsniff` at the tagged commit, by a GitHub-hosted runner, and cannot be tampered with after the fact.

## License

MIT
