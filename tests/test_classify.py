"""Tests for package/source classification."""

import json

from repolens.classify import classify
from repolens.models import FileDiff


def test_identical_file_is_expected():
    diff = FileDiff(
        path="src/index.js",
        status="identical",
    )

    finding = classify(diff)

    assert finding.classification == "EXPECTED"
    assert finding.explanation == "Package file is identical to source file."


def test_package_manifest_difference_is_unexplained():
    diff = FileDiff(
        path="package.json",
        status="modified",
    )

    finding = classify(diff)

    assert finding.classification == "UNEXPLAINED"
    assert finding.file_path == "package.json"


def test_dist_javascript_needs_verification():
    diff = FileDiff(
        path="dist/index.js",
        status="only_in_package",
    )

    finding = classify(diff)

    assert finding.classification == "UNEXPLAINED"
    assert "source mapping verification" in finding.explanation


def test_source_map_needs_verification():
    diff = FileDiff(
        path="dist/index.js.map",
        status="only_in_package",
    )

    finding = classify(diff)

    assert finding.classification == "UNEXPLAINED"
    assert "Source map requires verification" in finding.explanation


def test_unknown_difference_is_unexplained():
    diff = FileDiff(
        path="README.md",
        status="modified",
    )

    finding = classify(diff)

    assert finding.classification == "UNEXPLAINED"
    assert finding.file_path == "README.md"


def test_candidate_source_found_but_unverified():
    diff = FileDiff(
        path="dist/index.js",
        status="only_in_package",
    )
    finding = classify(diff, known_sources=["src/index.ts"])
    assert finding.classification == "UNEXPLAINED"
    assert "Candidate source found ('src/index.ts'); build relationship not verified." in finding.explanation


def test_build_output_no_candidate_source():
    diff = FileDiff(
        path="dist/orphan.js",
        status="only_in_package",
    )
    finding = classify(diff, known_sources=["src/index.ts"])
    assert finding.classification == "UNEXPLAINED"
    assert "has no candidate source file" in finding.explanation


def test_source_map_exact_sources_matched():
    diff = FileDiff(
        path="dist/index.js.map",
        status="only_in_package",
    )
    content = json.dumps({"version": 3, "sources": ["../src/index.ts"]})
    finding = classify(diff, known_sources=["src/index.ts"], content=content)
    assert finding.classification == "EXPECTED"
    assert "Source map references verified repository sources" in finding.explanation


def test_source_map_missing_source():
    diff = FileDiff(
        path="dist/index.js.map",
        status="only_in_package",
    )
    content = json.dumps({"version": 3, "sources": ["../src/missing.ts"]})
    finding = classify(diff, known_sources=["src/index.ts"], content=content)
    assert finding.classification == "UNEXPLAINED"
    assert "not found in source repository" in finding.explanation


def test_source_map_malformed_json():
    diff = FileDiff(
        path="dist/index.js.map",
        status="only_in_package",
    )
    finding = classify(diff, content="{not-valid-json")
    assert finding.classification == "UNEXPLAINED"
    assert finding.explanation == "Malformed source map JSON."


def test_source_map_empty_sources():
    diff = FileDiff(
        path="dist/index.js.map",
        status="only_in_package",
    )
    content = json.dumps({"version": 3, "sources": []})
    finding = classify(diff, content=content)
    assert finding.classification == "UNEXPLAINED"
    assert finding.explanation == "Source map contains no sources list."


def test_legitimate_bin_file_not_suspicious():
    diff = FileDiff(
        path="bin/cli.js",
        status="only_in_package",
    )
    finding = classify(diff)
    assert finding.classification == "UNEXPLAINED"
    assert finding.classification != "SUSPICIOUS"


def test_package_only_credential_file():
    diff = FileDiff(
        path=".env",
        status="only_in_package",
    )
    finding = classify(diff)
    assert finding.classification == "SUSPICIOUS"
    assert "Sensitive credential" in finding.explanation


def test_package_only_foreign_binary_executable():
    diff = FileDiff(
        path="tools/helper.exe",
        status="only_in_package",
    )
    finding = classify(diff)
    assert finding.classification == "SUSPICIOUS"
    assert "Executable binary or script format" in finding.explanation


def test_content_escalation_high_risk():
    diff = FileDiff(
        path="dist/helper.js",
        status="only_in_package",
    )
    # Hook (40) + eval (25) = 65 -> HIGH risk
    content = '"postinstall": "node setup.js"\neval(code);'
    finding = classify(diff, content=content)
    assert finding.classification == "SUSPICIOUS"
    assert finding.risk_level == "HIGH"
    assert "install lifecycle hook" in finding.signals
    assert "eval usage" in finding.signals


def test_content_medium_risk_remains_unexplained():
    diff = FileDiff(
        path="dist/helper.js",
        status="only_in_package",
    )
    # eval (25) -> MEDIUM risk
    content = "eval(code);"
    finding = classify(diff, content=content)
    assert finding.classification == "UNEXPLAINED"
    assert finding.risk_level == "MEDIUM"
    assert "eval usage" in finding.signals


def test_clean_content_maintains_status():
    diff = FileDiff(
        path="src/index.js",
        status="identical",
    )
    content = 'console.log("clean code");'
    finding = classify(diff, content=content)
    assert finding.classification == "EXPECTED"
    assert finding.risk_level == "LOW"
    assert finding.signals == []
