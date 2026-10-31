"""Tests for RepoLens command line interface."""

from pathlib import Path
import pytest
from typer.testing import CliRunner

from repolens.cli import app
from scripts.make_tampered import make_tampered_fixture

runner = CliRunner()


def test_cli_help():
    """1. CLI help works."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "RepoLens" in result.stdout
    assert "analyze" in result.stdout


def test_cli_analyze_no_package_dir():
    """2. Analyze without package-dir displays remote pipeline limitation."""
    result = runner.invoke(app, ["analyze", "lodash", "4.17.21"])
    assert result.exit_code == 0
    assert "Remote npm registry and repository fetch pipeline is not implemented yet" in result.stdout
    assert "--package-dir" in result.stdout


def test_cli_analyze_missing_package_dir(tmp_path: Path):
    """3. Analyze rejects missing package directory."""
    non_existent = tmp_path / "does_not_exist"
    result = runner.invoke(app, ["analyze", "pkg", "1.0.0", "--package-dir", str(non_existent)])
    assert result.exit_code != 0
    assert "does not exist" in result.output


def test_cli_analyze_invalid_source_dir(tmp_path: Path):
    """4. Analyze rejects invalid source directory."""
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    non_existent_src = tmp_path / "no_src"
    result = runner.invoke(
        app,
        [
            "analyze",
            "pkg",
            "1.0.0",
            "--package-dir",
            str(pkg_dir),
            "--source-dir",
            str(non_existent_src),
        ],
    )
    assert result.exit_code != 0
    assert "does not exist" in result.output


def test_cli_analyze_clean_fixture(tmp_path: Path):
    """5. Clean fixture can be analyzed."""
    fixture = make_tampered_fixture(tmp_path)
    result = runner.invoke(
        app,
        [
            "analyze",
            "clean-pkg",
            "1.0.0",
            "--package-dir",
            str(fixture["source_dir"]),
            "--source-dir",
            str(fixture["source_dir"]),
        ],
    )
    assert result.exit_code == 0
    assert "Overall Risk Level  : LOW" in result.stdout
    assert "EXPECTED" in result.stdout


def test_cli_analyze_simulated_package_fixture(tmp_path: Path):
    """6. Simulated package fixture can be analyzed."""
    fixture = make_tampered_fixture(tmp_path)
    result = runner.invoke(
        app,
        [
            "analyze",
            "tampered-pkg",
            "1.0.0",
            "--package-dir",
            str(fixture["package_dir"]),
            "--source-dir",
            str(fixture["source_dir"]),
        ],
    )
    assert result.exit_code == 0
    assert "RepoLens Analysis Report: tampered-pkg@1.0.0" in result.stdout


def test_cli_displays_risk_information(tmp_path: Path):
    """7. Package analysis displays risk information."""
    fixture = make_tampered_fixture(tmp_path)
    result = runner.invoke(
        app,
        [
            "analyze",
            "test-pkg",
            "1.0.0",
            "--package-dir",
            str(fixture["package_dir"]),
            "--source-dir",
            str(fixture["source_dir"]),
        ],
    )
    assert result.exit_code == 0
    assert "Overall Risk Level" in result.stdout
    assert "HIGH" in result.stdout


def test_cli_displays_classification_counts(tmp_path: Path):
    """8. Classification counts are displayed."""
    fixture = make_tampered_fixture(tmp_path)
    result = runner.invoke(
        app,
        [
            "analyze",
            "test-pkg",
            "1.0.0",
            "--package-dir",
            str(fixture["package_dir"]),
            "--source-dir",
            str(fixture["source_dir"]),
        ],
    )
    assert result.exit_code == 0
    assert "Classification Summary:" in result.stdout
    assert "EXPECTED" in result.stdout
    assert "UNEXPLAINED" in result.stdout
    assert "SUSPICIOUS" in result.stdout


def test_cli_displays_static_indicators(tmp_path: Path):
    """9. Static indicators are displayed."""
    fixture = make_tampered_fixture(tmp_path)
    result = runner.invoke(
        app,
        [
            "analyze",
            "test-pkg",
            "1.0.0",
            "--package-dir",
            str(fixture["package_dir"]),
            "--source-dir",
            str(fixture["source_dir"]),
        ],
    )
    assert result.exit_code == 0
    assert "Static Indicators Detected" in result.stdout
    assert "install lifecycle hook" in result.stdout
    assert "eval usage" in result.stdout


def test_cli_displays_source_verification_status(tmp_path: Path):
    """10. Source verification status is displayed."""
    fixture = make_tampered_fixture(tmp_path)

    # When source-dir is provided
    with_source = runner.invoke(
        app,
        [
            "analyze",
            "test-pkg",
            "1.0.0",
            "--package-dir",
            str(fixture["package_dir"]),
            "--source-dir",
            str(fixture["source_dir"]),
        ],
    )
    assert "Compared against local source repository" in with_source.stdout

    # When source-dir is omitted
    without_source = runner.invoke(
        app,
        [
            "analyze",
            "test-pkg",
            "1.0.0",
            "--package-dir",
            str(fixture["package_dir"]),
        ],
    )
    assert "No source repository provided (unverified)" in without_source.stdout


def test_cli_does_not_execute_code(tmp_path: Path, monkeypatch):
    """11. CLI does not execute generated fixture code."""
    import subprocess
    import os

    def forbidden(*args, **kwargs):
        raise AssertionError("Forbidden execution attempt in CLI!")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)

    fixture = make_tampered_fixture(tmp_path)
    result = runner.invoke(
        app,
        [
            "analyze",
            "safe-check",
            "1.0.0",
            "--package-dir",
            str(fixture["package_dir"]),
            "--source-dir",
            str(fixture["source_dir"]),
        ],
    )
    assert result.exit_code == 0


def test_cli_does_not_modify_fixture_files(tmp_path: Path):
    """12. CLI does not modify fixture files."""
    fixture = make_tampered_fixture(tmp_path)

    initial_bytes = {
        p: p.read_bytes()
        for p in fixture["package_dir"].rglob("*")
        if p.is_file()
    }

    result = runner.invoke(
        app,
        [
            "analyze",
            "test-pkg",
            "1.0.0",
            "--package-dir",
            str(fixture["package_dir"]),
            "--source-dir",
            str(fixture["source_dir"]),
        ],
    )
    assert result.exit_code == 0

    for p, b in initial_bytes.items():
        assert p.read_bytes() == b, f"File {p} was modified by CLI scan!"


def test_cli_positional_arguments_compatibility():
    """13. Existing analyze positional arguments remain compatible."""
    result = runner.invoke(app, ["analyze", "express", "4.18.2"])
    assert result.exit_code == 0
    assert "express@4.18.2" in result.stdout


def test_cli_unreadable_file_does_not_crash(tmp_path: Path):
    """14. One unreadable or unsupported binary file does not crash the entire scan."""
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "good.js").write_text("console.log('ok');", encoding="utf-8")

    # Add a file with arbitrary binary bytes that cannot decode as UTF-8
    binary_file = pkg_dir / "binary.dat"
    binary_file.write_bytes(b"\x00\xff\xfe\x01\x02\x03\x80\x90\xaa\xbb")

    result = runner.invoke(
        app,
        [
            "analyze",
            "binary-pkg",
            "1.0.0",
            "--package-dir",
            str(pkg_dir),
        ],
    )
    assert result.exit_code == 0
    assert "RepoLens Analysis Report: binary-pkg@1.0.0" in result.stdout
    assert "good.js" in result.stdout


def test_cli_risk_aggregation_multi_file_unique_signals(tmp_path: Path):
    """15. Verifies multi-file signal aggregation and avoids duplicate score inflation."""
    pkg_dir = tmp_path / "multi_pkg"
    pkg_dir.mkdir()

    # File 1 has eval (25)
    (pkg_dir / "a.js").write_text("eval(foo);", encoding="utf-8")
    # File 2 also has eval (25)
    (pkg_dir / "b.js").write_text("eval(bar);", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "analyze",
            "multi-pkg",
            "1.0.0",
            "--package-dir",
            str(pkg_dir),
        ],
    )
    assert result.exit_code == 0
    # Unique signals is only ["eval usage"] (score 25), so risk is MEDIUM, not falsely doubled to HIGH
    assert "Content Risk    : MEDIUM (Score: 25 from unique signals)" in result.stdout


def test_cli_symlink_traversal_protection(tmp_path: Path):
    """16. Verifies symlinks outside root directory are not followed."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "secret.env").write_text("SECRET=123", encoding="utf-8")

    pkg_dir = tmp_path / "sym_pkg"
    pkg_dir.mkdir()
    (pkg_dir / "index.js").write_text("console.log('hello');", encoding="utf-8")

    # Create symlink pointing outside
    symlink_file = pkg_dir / "linked_secret.env"
    symlink_file.symlink_to(outside_dir / "secret.env")

    result = runner.invoke(
        app,
        [
            "analyze",
            "symlink-pkg",
            "1.0.0",
            "--package-dir",
            str(pkg_dir),
        ],
    )
    assert result.exit_code == 0
    # linked_secret.env must be ignored and not scanned
    assert "linked_secret.env" not in result.stdout
