"""Integration test: run main() with mocked CSV downloads and verify output JSON."""

import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from src.ncsb.generate import log_orphan_baselines, main

FAKE_CONTROLS = pd.DataFrame(
    {
        "Control Identifier": ["AC-1", "AC-2", "AC-2(1)", "SC-7"],
        "Control Name": [
            "Policy and Procedures",
            "Account Management",
            "Account Management | Automated System Account Management",
            "Boundary Protection",
        ],
        "Control": [
            "Develop an access control policy.",
            "Define and manage system accounts.",
            "Support management of system accounts using automated mechanisms.",
            "Monitor and control communications at the boundary.",
        ],
        "Discussion": ["None.", "None.", "None.", "None."],
        "Related Controls": ["AC-2", "AC-3,AC-5", "AC-2", "AC-4,SC-8"],
    }
)

FAKE_LOW = pd.DataFrame({"Control Identifier": ["AC-1", "AC-2"]})
FAKE_MODERATE = pd.DataFrame({"Control Identifier": ["AC-1", "AC-2", "AC-2(1)", "SC-7"]})
FAKE_HIGH = pd.DataFrame({"Control Identifier": ["AC-1", "AC-2", "AC-2(1)", "SC-7"]})
FAKE_PRIVACY = pd.DataFrame({"Control Identifier": ["AC-1"]})


def _mock_download_csv(url: str) -> pd.DataFrame:
    """Return the appropriate fake DataFrame based on the URL substring."""
    lower = url.lower()
    if "catalog" in lower or "controls" in lower:
        return FAKE_CONTROLS.copy()
    if "low" in lower:
        return FAKE_LOW.copy()
    if "moderate" in lower:
        return FAKE_MODERATE.copy()
    if "high" in lower:
        return FAKE_HIGH.copy()
    if "privacy" in lower:
        return FAKE_PRIVACY.copy()
    raise ValueError(f"Unexpected URL in test: {url}")


@patch("src.ncsb.generate.download_csv", side_effect=_mock_download_csv)
def test_main_produces_valid_json(mock_dl):
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = str(Path(tmpdir) / "output.json")
        with patch("sys.argv", ["ncsb-generate", "--out", out_path]):
            main()

        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)

    assert data["project"] == "NIST Cloud Security Baseline (NCSB)"
    assert "project_version" in data
    assert "generated_at_utc" in data
    assert data["framework"] == "NIST SP 800-53 Rev. 5"
    assert "reference" in data
    assert "rules" in data
    assert isinstance(data["controls"], list)
    assert data["count"] == len(data["controls"])

    ids = [c["control_id"] for c in data["controls"]]
    assert ids == sorted(ids), "controls should be sorted by control_id"

    required_keys = {
        "control_id",
        "control_name",
        "family",
        "control_text",
        "discussion",
        "related_controls",
        "parent_control_id",
        "baseline_membership",
        "severity",
        "non_negotiable",
    }
    for ctrl in data["controls"]:
        assert required_keys.issubset(ctrl.keys())
        bm = ctrl["baseline_membership"]
        assert set(bm.keys()) == {"low", "moderate", "high", "privacy"}
        assert all(isinstance(v, bool) for v in bm.values())
        assert ctrl["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert isinstance(ctrl["non_negotiable"], bool)


@patch("src.ncsb.generate.download_csv", side_effect=_mock_download_csv)
def test_baseline_membership_accuracy(mock_dl):
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = str(Path(tmpdir) / "output.json")
        with patch("sys.argv", ["ncsb-generate", "--out", out_path]):
            main()

        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)

    by_id = {c["control_id"]: c for c in data["controls"]}

    ac1 = by_id["AC-1"]
    assert ac1["baseline_membership"] == {"low": True, "moderate": True, "high": True, "privacy": True}
    assert ac1["severity"] == "MEDIUM"
    assert ac1["non_negotiable"] is True

    sc7 = by_id["SC-7"]
    assert sc7["baseline_membership"] == {"low": False, "moderate": True, "high": True, "privacy": False}
    assert sc7["severity"] == "HIGH"
    assert sc7["non_negotiable"] is True


@patch("src.ncsb.generate.download_csv", side_effect=_mock_download_csv)
def test_enhancement_parent_linkage(mock_dl):
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = str(Path(tmpdir) / "output.json")
        with patch("sys.argv", ["ncsb-generate", "--out", out_path]):
            main()

        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)

    by_id = {c["control_id"]: c for c in data["controls"]}

    assert by_id["AC-2"]["parent_control_id"] is None
    assert by_id["AC-2(1)"]["parent_control_id"] == "AC-2"
    assert by_id["AC-2(1)"]["family"] == "AC"


@patch("src.ncsb.generate.download_csv", side_effect=_mock_download_csv)
def test_non_negotiable_high_only(mock_dl):
    """When --non_negotiable_min_baseline=high, only high-baseline controls are non-negotiable."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = str(Path(tmpdir) / "output.json")
        with patch("sys.argv", ["ncsb-generate", "--out", out_path, "--non_negotiable_min_baseline", "high"]):
            main()

        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)

    for ctrl in data["controls"]:
        if ctrl["baseline_membership"]["high"]:
            assert ctrl["non_negotiable"] is True
        else:
            assert ctrl["non_negotiable"] is False


def test_log_orphan_baselines_warns(caplog):
    catalog_ids = {"AC-1", "AC-2"}
    with caplog.at_level(logging.WARNING):
        log_orphan_baselines(
            catalog_ids,
            low={"AC-1", "AC-2"},
            moderate={"AC-1", "AC-2", "AC-99"},
            high={"AC-1"},
            privacy={"PM-1"},
        )
    assert "1 moderate-baseline" in caplog.text
    assert "AC-99" in caplog.text
    assert "1 privacy-baseline" in caplog.text
    assert "PM-1" in caplog.text
    assert "low-baseline" not in caplog.text
    assert "high-baseline" not in caplog.text


def test_log_orphan_baselines_silent_when_no_orphans(caplog):
    catalog_ids = {"AC-1", "AC-2"}
    with caplog.at_level(logging.WARNING):
        log_orphan_baselines(
            catalog_ids,
            low={"AC-1"},
            moderate={"AC-1", "AC-2"},
            high={"AC-2"},
            privacy=set(),
        )
    assert caplog.text == ""
