from repolens import __version__
from repolens.models import Finding, Report


def test_import():
    assert __version__


def test_models():
    f = Finding(path="a.js", label="EXPECTED", reason="identical")
    r = Report(package="x", version="1.0.0", source_found=True, findings=[f])
    assert r.risk == "LOW"
    assert r.findings[0].path == "a.js"
