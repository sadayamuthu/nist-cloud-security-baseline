# NIST Cloud Security Baseline (NCSB)

A Python tool that generates a **machine-readable, cloud-agnostic security baseline** from authoritative NIST publications. It merges the full NIST SP 800-53 Rev. 5 control catalog with the SP 800-53B baseline profiles and produces a single enriched JSON file ready for downstream automation.

## Why this exists

Cloud security teams need a common starting point that is vendor-neutral:

- **NIST SP 800-53 Rev. 5** defines *what* security controls exist (1,000+ controls and enhancements across 20 families like Access Control, Audit, System Protection, etc.).
- **NIST SP 800-53B** defines *which* controls belong to the Low, Moderate, High, and Privacy baselines.

These documents are published as separate CSVs on the NIST website. NCSB downloads them, joins the data, and enriches every control with baseline membership flags, a derived severity level, and a non-negotiable indicator — all in one JSON file you can feed into policy engines, compliance dashboards, IaC scanners, or cloud-provider mapping tools.

## Features

- **Zero configuration** — downloads source CSVs directly from NIST; no local data files to maintain.
- **Enriched output** — every control gets `severity` (LOW / MEDIUM / HIGH / CRITICAL) and `non_negotiable` (boolean) fields derived from configurable rules.
- **Baseline membership** — flags each control's presence in the Low, Moderate, High, and Privacy baselines.
- **Parent-enhancement linkage** — enhancement controls (e.g. `AC-2(1)`) are linked back to their parent (`AC-2`).
- **Configurable** — override any source URL or rule via CLI flags.
- **CI-ready** — ships with a GitHub Actions workflow that regenerates the baseline daily and commits the result.

## Quick start

```bash
# clone and set up
git clone https://github.com/<your-org>/nist-cloud-security-baseline.git
cd nist-cloud-security-baseline
python -m venv .venv
source .venv/bin/activate

# install (editable, with dev tools)
pip install -e ".[dev]"

# generate the enriched baseline
ncsb-generate --out examples/nist80053r5_full_catalog_enriched.json
```

Or run directly without installing as a package:

```bash
pip install pandas requests
python -m src.ncsb.generate --out examples/nist80053r5_full_catalog_enriched.json
```

## CLI options

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | `nist80053r5_full_catalog_enriched.json` | Output file path |
| `--non_negotiable_min_baseline` | `moderate` | Minimum baseline for `non_negotiable=true` (`moderate` or `high`) |
| `--controls_csv_url` | NIST catalog URL | Override the controls CSV source |
| `--baseline_low_csv_url` | NIST Low baseline URL | Override the Low baseline CSV |
| `--baseline_moderate_csv_url` | NIST Moderate baseline URL | Override the Moderate baseline CSV |
| `--baseline_high_csv_url` | NIST High baseline URL | Override the High baseline CSV |
| `--baseline_privacy_csv_url` | NIST Privacy baseline URL | Override the Privacy baseline CSV |
| `--version` | | Print version and exit |

## Output schema

The generated JSON has this top-level structure:

```json
{
  "project": "NIST Cloud Security Baseline (NCSB)",
  "project_version": "0.1.0",
  "generated_at_utc": "2026-02-18T06:00:00Z",
  "framework": "NIST SP 800-53 Rev. 5",
  "reference": { "publication": "...", "downloads": "..." },
  "rules": { "severity_definition": { ... }, "non_negotiable_min_baseline": "moderate" },
  "count": 1189,
  "controls": [ ... ]
}
```

Each item in `controls[]`:

| Field | Type | Example |
|-------|------|---------|
| `control_id` | string | `AC-2` or `AC-2(1)` |
| `control_name` | string | `Account Management` |
| `family` | string | `AC`, `AU`, `SC`, ... |
| `control_text` | string | Full control statement |
| `discussion` | string | Supplemental guidance |
| `related_controls` | string | Comma-separated IDs |
| `parent_control_id` | string or null | `AC-2` (for enhancements) |
| `baseline_membership` | object | `{ "low": true, "moderate": true, "high": true, "privacy": false }` |
| `severity` | string | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `non_negotiable` | boolean | `true` |

## Severity and non-negotiable rules

**Severity** is assigned based on the *earliest* (least restrictive) baseline a control appears in:

| Condition | Severity |
|-----------|----------|
| In Low baseline | `MEDIUM` |
| In Moderate (not Low) | `HIGH` |
| In High (not Low or Moderate) | `CRITICAL` |
| Privacy-only | `MEDIUM` |
| Not in any baseline | `LOW` |

**Non-negotiable** defaults to `true` when a control is in the Moderate or High baseline. Pass `--non_negotiable_min_baseline high` to restrict it to High-only.

## Project structure

```
nist-cloud-security-baseline/
├── src/ncsb/
│   ├── __init__.py          # package version
│   ├── __main__.py          # python -m entry point
│   ├── generate.py          # CLI and core logic
│   └── urls.py              # default NIST download URLs
├── tests/
│   ├── test_generate.py     # integration tests (mocked downloads)
│   └── test_normalize.py    # unit tests for ID normalization
├── baseline/                # generated output (committed by CI)
├── examples/                # local example output (git-ignored)
├── .github/workflows/
│   └── generate-baseline.yml
├── pyproject.toml
└── LICENSE
```

## Automation (GitHub Actions)

The workflow at `.github/workflows/generate-baseline.yml` runs:

- **On schedule** — daily at 06:00 UTC
- **On push** to `main`
- **On demand** via *Actions > Generate NIST Cloud Security Baseline > Run workflow*

Each run:

1. Runs the test suite across Python 3.11, 3.12, and 3.13.
2. Lints with [Ruff](https://docs.astral.sh/ruff/).
3. Generates `baseline/nist80053r5_full_catalog_enriched.json` (latest, always the same path) and archives a timestamped copy under `baseline/historical/`.
4. Commits and pushes the files back to the repo.
5. Creates a **GitHub Release** (tagged `baseline-YYYY-MM-DD`) with the JSON attached as a downloadable asset and detailed release notes including control count, framework version, and generation timestamp.

## Development

```bash
# install in editable mode with dev tools
pip install -e ".[dev]"

# run tests
pytest -v

# lint
ruff check src/ tests/

# format
ruff format src/ tests/
```

## Data sources

All data is fetched live from the official NIST downloads page:

- [NIST SP 800-53 Rev. 5 Downloads](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads)

If NIST changes file names or paths, update `src/ncsb/urls.py` or pass the correct URLs via CLI flags.

## License

MIT (for this repository's code). NIST content is public domain (U.S. Government work).
