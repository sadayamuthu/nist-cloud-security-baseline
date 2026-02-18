#!/usr/bin/env python3
"""
CLI: Generate an enriched NIST SP 800-53 Rev.5 catalog JSON
with NIST SP 800-53B baseline membership + derived severity/non-negotiable.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from dataclasses import dataclass
from io import StringIO
from typing import Dict, Any, Set, Optional

import pandas as pd
import requests

from . import __version__
from .urls import (
    CONTROLS_CSV_URL,
    BASELINE_LOW_CSV_URL,
    BASELINE_MODERATE_CSV_URL,
    BASELINE_HIGH_CSV_URL,
    BASELINE_PRIVACY_CSV_URL,
)

logger = logging.getLogger(__name__)

CONTROL_ID_RE = re.compile(r"^[A-Z]{2,3}-\d{1,3}$")
ENHANCEMENT_RE = re.compile(r"^([A-Z]{2,3}-\d{1,3})\((\d+)\)$")


def download_csv(url: str) -> pd.DataFrame:
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    content = r.content.decode("utf-8", errors="replace")
    return pd.read_csv(StringIO(content))


def normalize_id(raw: Any) -> str:
    if raw is None:
        return ""
    s = str(raw).strip().upper().replace(" ", "")
    m = ENHANCEMENT_RE.match(s)
    if m:
        base, num = m.group(1), str(int(m.group(2)))
        return f"{base}({num})"
    return s


def is_base(control_id: str) -> bool:
    return bool(CONTROL_ID_RE.match(control_id))


def parent_of(enh_id: str) -> Optional[str]:
    m = ENHANCEMENT_RE.match(enh_id)
    return m.group(1) if m else None


def family_of(control_id: str) -> str:
    base = parent_of(control_id) or control_id
    return base.split("-")[0]


def baseline_id_set(df: pd.DataFrame) -> Set[str]:
    df.columns = [c.strip() for c in df.columns]
    candidates = [
        "Control Identifier",
        "Control ID",
        "identifier",
        "Control",
        "Control Number",
        "Control Identifier (800-53)",
    ]
    col = next((c for c in candidates if c in df.columns), df.columns[0])
    return {normalize_id(v) for v in df[col].dropna().tolist() if normalize_id(v)}


def controls_catalog(df: pd.DataFrame) -> Dict[str, Dict[str, Any]]:
    df.columns = [c.strip() for c in df.columns]

    def pick(*names: str) -> Optional[str]:
        for n in names:
            if n in df.columns:
                return n
        return None

    id_col = pick("Control Identifier", "Control ID", "identifier", "Control")
    name_col = pick("Control Name", "Name", "name")
    control_text_col = pick("Control", "Control Text", "Statement", "control_text")
    discussion_col = pick("Discussion", "Supplemental Guidance", "discussion")
    related_col = pick("Related Controls", "Related", "related")

    if id_col is None:
        raise ValueError("Could not find a control identifier column in controls CSV.")

    out: Dict[str, Dict[str, Any]] = {}

    for _, row in df.iterrows():
        cid = normalize_id(row.get(id_col))
        if not cid:
            continue

        # keep only valid base controls and enhancements
        base = parent_of(cid) or cid
        if not (is_base(base) or ENHANCEMENT_RE.match(cid)):
            continue

        out[cid] = {
            "control_id": cid,
            "control_name": (str(row.get(name_col)).strip() if name_col else None),
            "family": family_of(cid),
            "control_text": (str(row.get(control_text_col)).strip() if control_text_col else None),
            "discussion": (str(row.get(discussion_col)).strip() if discussion_col else None),
            "related_controls": (str(row.get(related_col)).strip() if related_col else None),
            "parent_control_id": parent_of(cid),
        }

    return out


@dataclass
class Rules:
    non_negotiable_min_baseline: str = "moderate"  # "moderate" or "high"
    severity_low: str = "MEDIUM"
    severity_moderate: str = "HIGH"
    severity_high: str = "CRITICAL"
    severity_privacy_only: str = "MEDIUM"
    severity_none: str = "LOW"


def membership_flags(cid: str, low: Set[str], moderate: Set[str], high: Set[str], privacy: Set[str]) -> Dict[str, bool]:
    return {
        "low": cid in low,
        "moderate": cid in moderate,
        "high": cid in high,
        "privacy": cid in privacy,
    }


def severity_from_membership(m: Dict[str, bool], rules: Rules) -> str:
    if m["low"]:
        return rules.severity_low
    if m["moderate"]:
        return rules.severity_moderate
    if m["high"]:
        return rules.severity_high
    if m["privacy"] and not (m["low"] or m["moderate"] or m["high"]):
        return rules.severity_privacy_only
    return rules.severity_none


def non_negotiable_from_membership(m: Dict[str, bool], rules: Rules) -> bool:
    if rules.non_negotiable_min_baseline.lower() == "high":
        return bool(m["high"])
    return bool(m["moderate"] or m["high"])


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ncsb-generate", description="Generate NIST Cloud Security Baseline JSON")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    p.add_argument("--controls_csv_url", default=CONTROLS_CSV_URL)
    p.add_argument("--baseline_low_csv_url", default=BASELINE_LOW_CSV_URL)
    p.add_argument("--baseline_moderate_csv_url", default=BASELINE_MODERATE_CSV_URL)
    p.add_argument("--baseline_high_csv_url", default=BASELINE_HIGH_CSV_URL)
    p.add_argument("--baseline_privacy_csv_url", default=BASELINE_PRIVACY_CSV_URL)

    p.add_argument("--non_negotiable_min_baseline", choices=["moderate", "high"], default="moderate")
    p.add_argument("--out", default="nist80053r5_full_catalog_enriched.json")

    return p


def log_orphan_baselines(
    catalog_ids: Set[str],
    *,
    low: Set[str],
    moderate: Set[str],
    high: Set[str],
    privacy: Set[str],
) -> None:
    """Warn about baseline control IDs that don't appear in the catalog."""
    baselines = {"low": low, "moderate": moderate, "high": high, "privacy": privacy}
    for name, id_set in baselines.items():
        orphans = sorted(id_set - catalog_ids)
        if orphans:
            logger.warning(
                "%d %s-baseline control(s) not found in catalog: %s",
                len(orphans),
                name,
                ", ".join(orphans),
            )


def main() -> None:
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.WARNING)
    args = build_arg_parser().parse_args()
    rules = Rules(non_negotiable_min_baseline=args.non_negotiable_min_baseline)

    controls_df = download_csv(args.controls_csv_url)
    low_df = download_csv(args.baseline_low_csv_url)
    mod_df = download_csv(args.baseline_moderate_csv_url)
    high_df = download_csv(args.baseline_high_csv_url)
    priv_df = download_csv(args.baseline_privacy_csv_url)

    controls = controls_catalog(controls_df)
    low = baseline_id_set(low_df)
    moderate = baseline_id_set(mod_df)
    high = baseline_id_set(high_df)
    privacy = baseline_id_set(priv_df)

    log_orphan_baselines(
        set(controls.keys()),
        low=low,
        moderate=moderate,
        high=high,
        privacy=privacy,
    )

    enriched = []
    for cid, rec in sorted(controls.items(), key=lambda x: x[0]):
        m = membership_flags(cid, low, moderate, high, privacy)
        rec_out = dict(rec)
        rec_out["baseline_membership"] = m
        rec_out["severity"] = severity_from_membership(m, rules)
        rec_out["non_negotiable"] = non_negotiable_from_membership(m, rules)
        enriched.append(rec_out)

    out_obj = {
        "project": "NIST Cloud Security Baseline (NCSB)",
        "project_version": __version__,
        "generated_at_utc": __import__("datetime").datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "framework": "NIST SP 800-53 Rev. 5",
        "reference": {
            "publication": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
            "downloads": "https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads",
        },
        "rules": {
            "severity_definition": {
                "if_in_low": rules.severity_low,
                "elif_in_moderate": rules.severity_moderate,
                "elif_in_high": rules.severity_high,
                "elif_privacy_only": rules.severity_privacy_only,
                "else": rules.severity_none,
            },
            "non_negotiable_min_baseline": rules.non_negotiable_min_baseline,
        },
        "count": len(enriched),
        "controls": enriched,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, ensure_ascii=False, indent=2)

    print(f"Wrote {len(enriched)} controls to {args.out}")


if __name__ == "__main__":
    main()
