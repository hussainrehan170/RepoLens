from repolens import __version__
from repolens.models import FileDiff, Finding, Report


def test_import():
    assert __version__


def test_models():
    d = FileDiff(path="a.js", status="identical")
    f = Finding(file_path="a.js", classification="EXPECTED")
    r = Report(package_name="x", version="1.0.0", repo_url=None, commit_or_tag=None,
               overall_verdict="CLEAN", overall_risk_score=0, findings=[f])
    assert d.package_sha256 is None
    assert r.overall_verdict == "CLEAN"
    assert r.findings[0].file_path == "a.js"
