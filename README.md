# NIST Cloud Security Baseline (NCSB)

A small tool that generates a **cloud-agnostic security baseline dataset** derived from:

- **NIST SP 800-53 Rev. 5** (full control catalog: base + enhancements)
- **NIST SP 800-53B** (Low / Moderate / High / Privacy baselines)

It outputs a single **enriched JSON** file that includes:
- Control metadata (id, name, family, text, discussion, related controls)
- Parent → enhancement linkage
- Baseline membership flags (low/moderate/high/privacy)
- Derived `severity` and `non_negotiable` fields using configurable rules

## Why this exists

NIST defines the **what** (controls and baselines). Cloud providers define the **how** (AWS/Azure/GCP implementations).
This project produces a machine-readable **NIST Cloud Security Baseline** that you can map to any cloud.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m src.ncsb.generate \
  --out examples/nist80053r5_full_catalog_enriched.json
```

## Output schema (high level)

Each item in `controls[]` includes:

- `control_id` (e.g., `AC-2` or `AC-2(1)`)
- `control_name`
- `family` (e.g., `AC`, `AU`, `SC`)
- `control_text`
- `discussion`
- `related_controls`
- `parent_control_id` (for enhancements)
- `baseline_membership` {low, moderate, high, privacy}
- `severity` (LOW/MEDIUM/HIGH/CRITICAL)
- `non_negotiable` (boolean)

## Rules

Default rules:
- Severity is based on the **earliest** baseline a control appears in:
  - in Low → MEDIUM
  - else in Moderate → HIGH
  - else in High → CRITICAL
  - privacy-only → MEDIUM
  - none → LOW
- Non-negotiable is `true` if control is in **Moderate or High**.
  (You can switch this to `--non_negotiable_min_baseline high`.)

## Automation (GitHub Actions)

A GitHub Actions workflow (`.github/workflows/generate-baseline.yml`) runs the
generator daily and on every push to `main`. Each run writes a timestamped JSON
file to the `baseline/` directory, e.g.
`baseline/nist80053r5_full_catalog_enriched_2026-02-18T06-00-00Z.json`,
and commits it back to the repo. You can also trigger it manually via
**Actions > Generate NIST Cloud Security Baseline > Run workflow**.

## Source of truth

NIST downloads page:
- https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads

> Note: NIST may occasionally change file names/paths. If a download URL breaks, update `src/ncsb/urls.py`
> or override URLs via CLI flags.

## License

MIT (for this repo's code). NIST content is public domain (US Government work).
