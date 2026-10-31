import io
import json
import tarfile

from typer.testing import CliRunner

from repolens.cli import app
from repolens.models import Finding
from repolens.pipeline import compute_verdict, run_pipeline

PJ = json.dumps({"name": "x", "version": "1.0.0"})


def make_tgz(path, files):
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            ti = tarfile.TarInfo("package/" + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))


def test_missing_source_gives_finding_not_crash(tmp_path):
    t = tmp_path / "p.tgz"
    make_tgz(t, {"package.json": PJ, "index.js": "1"})
    r = run_pipeline(None, None, str(tmp_path / "w"), tarball=str(t))
    assert r.package_name == "x" and r.version == "1.0.0"
    assert any(f.signals == ["SOURCE_NOT_FOUND"] for f in r.findings)
    assert r.overall_verdict == "WARNING"


def test_local_source_dir(tmp_path):
    t, src = tmp_path / "p.tgz", tmp_path / "src"
    src.mkdir()
    (src / "index.js").write_text("1")
    (src / "package.json").write_text(PJ)
    make_tgz(t, {"package.json": PJ, "index.js": "1", "extra.js": "2"})
    r = run_pipeline(None, None, str(tmp_path / "w"), tarball=str(t), source_dir=str(src))
    assert r.metadata["file_counts"]["identical"] == 2
    assert [f.file_path for f in r.findings] == ["extra.js"]


def test_verdict_thresholds():
    assert compute_verdict([])[0] == "CLEAN"
    assert compute_verdict([Finding("a", "UNEXPLAINED", risk_level="MEDIUM")])[0] == "WARNING"
    assert compute_verdict([Finding("a", "SUSPICIOUS", risk_level="HIGH")])[0] == "SUSPICIOUS"
    assert compute_verdict([Finding("a", "EXPECTED", risk_level="HIGH")])[0] == "CLEAN"


def test_cli_analyze_local_tarball(tmp_path):
    t = tmp_path / "p.tgz"
    make_tgz(t, {"package.json": PJ, "index.js": "1"})
    out = tmp_path / "o"
    result = CliRunner().invoke(app, ["analyze", "--tarball", str(t), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "report.json").exists()


def test_many_medium_findings_are_only_a_warning():
    many = [Finding(f"f{i}.js", "UNEXPLAINED", risk_level="MEDIUM") for i in range(1000)]
    verdict, score = compute_verdict(many)
    assert verdict == "WARNING" and score == 30
