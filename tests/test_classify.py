"""Tests for package/source classification."""

from repolens.classify import classify
from repolens.models import FileDiff


def test_identical_file_is_expected():
    diff = FileDiff(
        path="src/index.js",
        status="identical",
    )

    finding = classify(diff)

    assert finding.label == "EXPECTED"
    assert finding.reason == "Package file is identical to source file."


def test_package_manifest_difference_is_unexplained():
    diff = FileDiff(
        path="package.json",
        status="modified",
    )

    finding = classify(diff)

    assert finding.label == "UNEXPLAINED"
    assert finding.path == "package.json"


def test_dist_javascript_needs_verification():
    diff = FileDiff(
        path="dist/index.js",
        status="only_in_package",
    )

    finding = classify(diff)

    assert finding.label == "UNEXPLAINED"
    assert "source mapping verification" in finding.reason


def test_source_map_needs_verification():
    diff = FileDiff(
        path="dist/index.js.map",
        status="only_in_package",
    )

    finding = classify(diff)

    assert finding.label == "UNEXPLAINED"
    assert "Source map requires verification" in finding.reason


def test_unknown_difference_is_unexplained():
    diff = FileDiff(
        path="README.md",
        status="modified",
    )

    finding = classify(diff)

    assert finding.label == "UNEXPLAINED"
    assert finding.path == "README.md"
