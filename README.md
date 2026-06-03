# DeepSecrets 2.0 - a better tool for secrets scanning

![Tests Status](https://github.com/ntoskernel/deepsecrets/actions/workflows/run-tests.yml/badge.svg)

## What is it? Another token-wasting CLI proxy to an AI API?

Absolutely not!

In our LLM-hype era, DeepSecrets still runs entirely on your machine — giving you great results offline, securely, and for free.


## So why yet another tool?
Most existing scanners don't actually "understand" code. Instead, they just parse texts and have bad coverage.

DeepSecrets bridges the gap between classic regex scanners and full-scale commercial SAST tools. It extends the classic regex-based scanning strategy by heavily relying on semantic code analysis, dangerous variable detection, and context-aware entropy analysis.
This means secret candidates are always semantically correct. We achieve true code understanding across 500+ languages and formats using lexing and parsing techniques

DeepSecrets also introduces a new way to find credentials: the HashedSecret Engine. Just provide the hashed values of your known production secrets, and the tool will find them exposed in plain text within your code.

### Performance & Benchmarks (SecretBench)

DeepSecrets v2.0 was evaluated (May 2026) against the **SecretBench** benchmark outperforming traditional flat-text scanners:

* **93% Recall** 
* **8% False Positive Rate** on SecretBench scope
* **~9K Extra Findings** *outside* the benchmark scope due to deep semantic code parsing

(You can read the full under-the-hood story and benchmark breakdown in my HackerNoon article here: Modernizing Secrets Scanning)


# Quick Start Guide

## Installation

From Github via pip

```bash
$ pip install git+https://github.com/ntoskernel/deepsecrets.git
```

From PyPi

```bash
$ pip install deepsecrets
```


## Scanning
The easiest way to run a scan:

```bash
$ deepsecrets --target-dir /path/to/your/code --outformat dojo-sarif --outfile report.json
```

This will run a scan against `/path/to/your/code` using the default configuration:
- Regex using the built-in ruleset
- Semantic checks (variable detection, entropy checks)

A report in SARIF format (compatible with DefectDojo and GitHub Security) will be saved to report.json.

### Fine-Tuning
The `--help` command is always ready to guide you, but here are the key flags you can use to tailor the scan to your environment:
* `--regex-rules /path/to/rules.json`: Supply your own custom regex ruleset.
* `--hashed-values /path/to/hashes.json`: Provide a list of pre-hashed known production secrets to search for them securely.
* `--excluded-paths /path/to/exclusions.json`: Override or extend the default paths ignored during scanning.
* `--disable-masking`: Keep potential secrets unmasked in the output report *(see caution below)*.


### Github Actions Integration

eq. `.github/workflows/deepsecrets.yml`

```yaml
name: DeepSecrets Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install DeepSecrets
        run: pip install deepsecrets

      - name: Run Scan
        run: deepsecrets --target-dir . --outformat dojo-sarif --outfile report.sarif
        continue-on-error: true

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
```

### Masking secrets inside a report

As of version 1.3.0 all potential secrets inside reports are masked by default, but you can turn this feature off via the `--disable-masking` flag.

> [!Caution]  
> If you decide to integrate DeepSecrets to your CI pipeline with masking disabled, you will likely re-leak your secrets inside your CI artifacts.

### SARIF reports and the "Confidence" Parameter

DeepSecrets calculates and reports a granular confidence score for every discovered secret. Due to the constraints of the SARIF specification and variations in how different industry platforms parse it, DeepSecrets has the following features to ensure compatibility:

* **Virtual Subrules (`rules[]`)**: GitHub and DefectDojo parse security metrics primarily from the static rules array. To support this, DeepSecrets dynamically maps findings to "virtual" subrules (e.g., `S105-LOW`, `S105-MEDIUM`). Each subrule contains tailored `properties.precision` (strictly matching GitHub's allowed vocabulary) and a scaled `properties.security-severity` score (9.0–10.0), guaranteeing that **all** alerts are flagged as **Critical** in GitHub Security and DefectDojo, while preserving internal confidence variance.

* **Deterministic Result Level**: The tool always explicitly sets `level: error` in the `results[]` model. This acts as a universal fallback for CI/CD pipelines and older SAST parsers, ensuring that exposed secrets reliably break builds or block Pull Requests regardless of individual rule interpretations.

* **Contextual Messages**: The raw numeric confidence score is injected directly into `result.message.text` (and saved under `result.properties.confidence`). This ensures that security analysts can instantly see the exact confidence level inside any UI dashboard, even if the platform ignores custom JSON parameters.


## Building rulesets

### Regex

The built-in ruleset for regex checks is located in `/deepsecrets/rules/regexes.json`. You're free to follow the format and create a custom ruleset.

### HashedSecret

Example ruleset for hashed checks is located in `/tests/fixtures/hashed_secrets.json`. You're free to follow the format and create a custom ruleset.

#### HashedSecret Ruleset Example

To look for known production secrets without exposing them in plaintext inside your repository, provide a JSON containing their hashes:

```json
[
  {
    "name": "KNOWN-PROD-DATABASE-PASSWORD",
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "length": 12,
    "algorithm": "sha1"
  }
]
```
Run with `--hashed-values /path/to/hashes.json`. DeepSecrets will automatically hash token candidates during scanning and flag plain-text matches.

## Contacts

- Nikolai Khechumov ([@ntoskernel](https://github.com/ntoskernel)) — creator and maintainer

## FAQ
> Pff, is it still regex-based?

Yes and no. Of course, it uses regexes to find typed secrets like any other tool. But language understanding (the lexing stage) and variable detection also use regexes under the hood. Regex is an instrument, not the problem. The problem is applying regex blindly without semantic context.

> But what about Semgrep Secrets? Looks like you're cloning their thing.

DeepSecrets was released in April 2023 — half a year before the Semgrep Secrets release, and I'm very glad to be followed. We share similar ideas and principles under the hood, but DeepSecrets is free/open-source, and our code analysis is much wider, not limited to a specific subset of languages like Semgrep.

### DeepSecrets vs. Other Scanners

Most traditional scanners look at code as flat text, leading to massive alert fatigue (false positives) or missed leaked variables. DeepSecrets bridges the gap between classic regex scanners and full-scale commercial SAST tools.

#### Benchmark Results (SecretBench)
In recent evaluations against the **SecretBench** benchmark, DeepSecrets demonstrated industry-leading accuracy:
* **93% Recall (Sensitivity):** Caught almost all valid secrets within the benchmark.
* **8% False Positive Rate:** Minimal noise compared to traditional entropy-based scanners.
* **40,000+ Extra Findings:** Discovered tens of thousands of real, high-privilege credentials outside the baseline benchmark scope due to deep semantic code parsing.


| Feature / Capability | **DeepSecrets 2.0** | **Gitleaks** | **TruffleHog** | **Semgrep Secrets** |
| :--- | :---: | :---: | :---: | :---: |
| **SecretBench Accuracy** | **93% Recall<br>69% Precision** | 88% Recall<br>46% Precision | 52% Recall<br>6% Precision | *Not Evaluated* |
| **Price & Licensing** | **Free / Open-Source** | Free / Open-Source | Free / Open-Source | Commercial / Paid |
| **Analysis Type** | **Semantic / Regex** | Flat-text Regex / Entropy | Flat-text Regex / Entropy | Semantic |
| **Language Support** | **500+** | Context-agnostic (Text) | Context-agnostic (Text) | Limited subset |
| **Pre-hashed Validation** | **Yes (via Hashed Engine)** | No | No | No |
| **Context-Aware Entropy**| **Yes (Assigned values)** | No (Entire file text) | No (Entire file text) | Yes |
| **Advanced SARIF Output**| **Yes (Dynamic Confidence)** | Basic | Basic | Yes |

### Why this matters under the hood
* **True Code Understanding:** Traditional tools will flag high-entropy strings inside a comment or a base64 asset. DeepSecrets understands the semantic role of a token (e.g., if it is an assigned variable name like `db_password`), ensuring that candidates are always semantically correct.
* **Unmatched Discovery Width:** While Semgrep relies on specific language parsers and standard tools scan only what they know, DeepSecrets leverages 500+ lexers. This allows it to surface hidden, dangerous credentials in rare configuration formats and custom code blocks that benchmarks don't even have datasets for.


> Why don't you build true abstract syntax trees? It's academically more correct!

DeepSecrets tries to keep a balance between complexity and effectiveness. Building a true AST across 500+ languages is incredibly complex and simply overkill for the specific task of finding secrets. The tool follows the generic SAST approach to code analysis but optimizes the AST stage for maximum speed and width.

> I'd like to build my own semantic rules. How do I do that?

Semantic rules are now effectively "variable evaluation rules". You can find them [here](https://github.com/ntoskernel/deepsecrets/blob/main/deepsecrets/rules/variable_scoring_rules.json).

> I still have a question

Feel free to communicate with the [maintainer (emails available in pyproject.toml)](https://github.com/ntoskernel/deepsecrets/blob/main/pyproject.toml#L6-L8)



## Contributing

### Under the hood
There are several core concepts:

- `File`
- `Tokenizer`
- `Token`
- `Engine`
- `Finding`
- `ScanMode`

### File
Just a pythonic representation of a file with all needed methods for management.

### Tokenizer
A component able to break the content of a file into pieces - Tokens - by its logic. There are four types of tokenizers available:

- `FullContentTokenizer`: treats all content as a single token. Useful for regex-based search.
- `PerWordTokenizer`: breaks given content by words and line breaks.
- `LexerTokenizer`: uses language-specific smarts to break code into semantically correct pieces with additional context for each token.

### Token
A string with additional information about its semantic role, corresponding file, and location inside it.

### Engine
A component performing secrets search for a single token by its own logic. Returns a set of Findings. There are three engines available:

- `RegexEngine`: checks tokens' values through a special ruleset
- `SemanticEngine`: checks tokens produced by the LexerTokenizer using additional context - variable names and values
- `HashedSecretEngine`: checks tokens' values by hashing them and trying to find coinciding hashes inside a special ruleset

### Finding
This is a data structure representing a problem detected inside code. Features information about the precise location inside a file and a rule that found it.

### ScanMode
This component is responsible for the scan process.

- Defines the scope of analysis for a given work directory respecting exceptions
- Allows declaring a `PerFileAnalyzer` - the method called against each file, returning a list of findings. The primary usage is to initialize necessary engines, tokenizers, and rulesets.
- Runs the scan: a multiprocessing pool analyzes every file in parallel.
- Prepares results for output and outputs them.

The current implementation has a `CliScanMode` built by the user-provided config through the cli args.

### Local development

The project is supposed to be developed using VSCode and 'Remote containers' feature.

Steps:
1. Clone the repository
2. Open the cloned folder with VSCode
3. Agree with 'Reopen in container'
4. Wait until the container is built and necessary extensions are installed
5. You're ready