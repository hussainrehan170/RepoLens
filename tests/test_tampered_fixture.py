"""Tests for static harmless tampered package fixture generator."""

import json
from pathlib import Path
import pytest

from repolens.classify import classify
from repolens.models import FileDiff
from repolens.signals import analyze_content, inspect_content
import scripts.make_tampered as make_tampered_mod
from scripts.make_tampered import make_tampered_fixture


def test_creates_expected_directories(tmp_path: Path):
    """1. The generator creates the expected source and package directories."""
    fixture = make_tampered_fixture(tmp_path)

    assert fixture["source_dir"].is_dir()
    assert fixture["package_dir"].is_dir()
    assert (fixture["source_dir"] / "src").is_dir()
    assert (fixture["package_dir"] / "dist").is_dir()


def test_clean_source_files_exist(tmp_path: Path):
    """2. The clean source files exist."""
    fixture = make_tampered_fixture(tmp_path)

    assert fixture["source_package_json"].is_file()
    assert fixture["source_readme"].is_file()
    assert fixture["source_index_ts"].is_file()


def test_simulated_package_files_exist(tmp_path: Path):
    """3. The simulated package files exist."""
    fixture = make_tampered_fixture(tmp_path)

    assert fixture["package_package_json"].is_file()
    assert fixture["package_readme"].is_file()
    assert fixture["package_index_js"].is_file()
    assert fixture["package_index_map"].is_file()
    assert fixture["package_env"].is_file()
    assert fixture["package_exe"].is_file()
    assert fixture["package_minified"].is_file()
    assert fixture["package_entropy"].is_file()


def test_package_manifest_lifecycle_indicator(tmp_path: Path):
    """4. The package manifest contains the intended inert lifecycle indicator."""
    fixture = make_tampered_fixture(tmp_path)

    manifest_content = fixture["package_package_json"].read_text(encoding="utf-8")
    data = json.loads(manifest_content)

    assert "postinstall" in data["scripts"]
    assert data["scripts"]["postinstall"] == "node setup.js"
    assert "install lifecycle hook" in inspect_content(manifest_content)


def test_javascript_static_signals(tmp_path: Path):
    """5. The generated JavaScript contains the intended static signal strings."""
    fixture = make_tampered_fixture(tmp_path)

    content = fixture["package_index_js"].read_text(encoding="utf-8")
    signals = inspect_content(content)

    assert "eval usage" in signals
    assert "child_process usage" in signals
    assert "environment access" in signals


def test_source_map_resolves_to_source_tree(tmp_path: Path):
    """6. The source map is valid JSON and its source path resolves consistently to the clean source tree."""
    fixture = make_tampered_fixture(tmp_path)

    content = fixture["package_index_map"].read_text(encoding="utf-8")
    data = json.loads(content)

    assert data["version"] == 3
    assert data["sources"] == ["../src/index.ts"]

    # 1. Verify physical file exists in clean source tree
    resolved_source_file = fixture["source_dir"] / "src" / "index.ts"
    assert resolved_source_file.is_file()

    # 2. Verify logical path resolution from the map directory ('dist')
    # posixpath.normpath(posixpath.join("dist", "../src/index.ts")) -> "src/index.ts"
    known_sources = ["src/index.ts", "package.json", "README.md"]
    diff = FileDiff(path="dist/index.js.map", status="only_in_package")
    finding = classify(diff, known_sources=known_sources, content=content)

    # 3. Path-level reference matching confirms the map points to a repository source,
    # without asserting byte-for-byte build identity
    assert finding.label == "EXPECTED"
    assert "Source map references verified repository sources" in finding.reason


def test_env_contains_only_fake_placeholder(tmp_path: Path):
    """7. The .env contains only the fake placeholder."""
    fixture = make_tampered_fixture(tmp_path)

    env_content = fixture["package_env"].read_text(encoding="utf-8")
    assert "TEST_SECRET=fixture_dummy_not_a_real_secret" in env_content
    assert "SYNTHETIC TEST FIXTURE" in env_content

    # Verify classification as package-only sensitive credential
    diff = FileDiff(path=".env", status="only_in_package")
    finding = classify(diff)
    assert finding.label == "SUSPICIOUS"


def test_exe_is_plain_text_marker(tmp_path: Path):
    """8. The .exe-named file is a plain-text marker, not a real executable."""
    fixture = make_tampered_fixture(tmp_path)

    exe_bytes = fixture["package_exe"].read_bytes()
    # Not an executable binary format (e.g. no PE MZ header or ELF header)
    assert not exe_bytes.startswith(b"MZ")
    assert not exe_bytes.startswith(b"\x7fELF")
    assert "SYNTHETIC TEST FIXTURE - PLAIN TEXT MARKER" in fixture["package_exe"].read_text(encoding="utf-8")

    # Verify classification as package-only foreign executable format
    diff = FileDiff(path="helper.exe", status="only_in_package")
    finding = classify(diff)
    assert finding.label == "SUSPICIOUS"


def test_minified_fixture_length(tmp_path: Path):
    """9. The minified fixture contains a sufficiently long line for the existing detector."""
    fixture = make_tampered_fixture(tmp_path)

    content = fixture["package_minified"].read_text(encoding="utf-8")
    lines = content.splitlines()

    assert any(len(line) >= 500 for line in lines)
    assert "minified content" in inspect_content(content)


def test_high_entropy_fixture_deterministic(tmp_path: Path):
    """10. The high-entropy fixture is deterministic and exercises the existing entropy detector."""
    fixture = make_tampered_fixture(tmp_path)

    content = fixture["package_entropy"].read_text(encoding="utf-8")
    signals = inspect_content(content)

    assert "high-entropy content" in signals


def test_refuse_overwrite_non_empty_directory(tmp_path: Path):
    """11. The generator does not overwrite an existing non-empty output directory."""
    make_tampered_fixture(tmp_path)

    # Calling again on existing non-empty directory must raise FileExistsError
    with pytest.raises(FileExistsError, match="Output source directory already exists"):
        make_tampered_fixture(tmp_path)


def test_deterministic_runs_produce_identical_content(tmp_path: Path):
    """12. Two runs in separate empty directories produce equivalent file paths and file contents."""
    dir_a = tmp_path / "run_a"
    dir_b = tmp_path / "run_b"

    fixture_a = make_tampered_fixture(dir_a)
    fixture_b = make_tampered_fixture(dir_b)

    assert fixture_a.keys() == fixture_b.keys()
    for key in fixture_a:
        path_a = fixture_a[key]
        path_b = fixture_b[key]
        if path_a.is_file():
            assert path_a.read_bytes() == path_b.read_bytes(), f"Content mismatch in {key}"


def test_generator_does_not_execute_or_spawn_subprocesses(tmp_path: Path, monkeypatch):
    """13. The fixture generator itself does not execute suspicious strings or launch subprocesses."""
    # Ensure subprocess or os.system are never called by the generator
    import subprocess
    import os

    def forbidden_call(*args, **kwargs):
        raise AssertionError("Subprocess execution is strictly forbidden in fixture generator!")

    monkeypatch.setattr(subprocess, "Popen", forbidden_call)
    monkeypatch.setattr(subprocess, "run", forbidden_call)
    monkeypatch.setattr(os, "system", forbidden_call)

    # Verify make_tampered_mod does not import subprocess
    assert not hasattr(make_tampered_mod, "subprocess")

    # Run generator safely
    sub_dir = tmp_path / "safe_run"
    make_tampered_fixture(sub_dir)
    assert (sub_dir / "package").is_dir()
