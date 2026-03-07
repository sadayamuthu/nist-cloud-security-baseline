"""Tests for ncsb.cli dispatcher."""

import pytest

from ncsb.cli import main


def test_cli_fetch_dispatches_to_fetch_main(tmp_path):
    from unittest.mock import patch

    out_path = str(tmp_path / "out.json")
    with patch("ncsb.cli.fetch_main") as mock_fetch, patch("sys.argv", ["ncsb", "fetch", "--out", out_path]):
        main()
    mock_fetch.assert_called_once()
    args = mock_fetch.call_args[0][0]
    assert args.out == out_path


def test_cli_fetch_default_out():
    from unittest.mock import patch

    with patch("ncsb.cli.fetch_main") as mock_fetch, patch("sys.argv", ["ncsb", "fetch"]):
        main()
    args = mock_fetch.call_args[0][0]
    assert args.out == "nist80053r5_full_catalog_enriched.json"


def test_cli_generate_dispatches_to_generate_main(tmp_path):
    from unittest.mock import patch

    out_path = str(tmp_path / "out.json")
    with patch("ncsb.cli.generate_main") as mock_gen, patch("sys.argv", ["ncsb", "generate", "--out", out_path]):
        main()
    mock_gen.assert_called_once()
    args = mock_gen.call_args[0][0]
    assert args.out == out_path


def test_cli_generate_passes_non_negotiable_flag(tmp_path):
    from unittest.mock import patch

    out_path = str(tmp_path / "out.json")
    with (
        patch("ncsb.cli.generate_main") as mock_gen,
        patch("sys.argv", ["ncsb", "generate", "--out", out_path, "--non_negotiable_min_baseline", "high"]),
    ):
        main()
    args = mock_gen.call_args[0][0]
    assert args.non_negotiable_min_baseline == "high"


def test_cli_no_subcommand_exits():
    from unittest.mock import patch

    with pytest.raises(SystemExit), patch("sys.argv", ["ncsb"]):
        main()


def test_cli_version_exits(capsys):
    from unittest.mock import patch

    with pytest.raises(SystemExit) as exc_info, patch("sys.argv", ["ncsb", "--version"]):
        main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "ncsb" in captured.out
