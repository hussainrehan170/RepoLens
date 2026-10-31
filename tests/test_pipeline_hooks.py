from repolens.classify import classify_diffs
from repolens.models import FileDiff
from repolens.signals import apply_signals


def test_classify_diffs_flags_new_install_hook(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "setup.js").write_text('"postinstall": "node x.js"\neval(code);')
    diffs = [
        FileDiff(path="setup.js", status="only_in_package"),
        FileDiff(path="same.js", status="identical"),
    ]
    findings = classify_diffs(diffs, str(tmp_path), str(pkg))
    assert len(findings) == 1
    assert findings[0].file_path == "setup.js"
    assert findings[0].risk_level == "HIGH"
    assert findings[0].classification == "SUSPICIOUS"


def test_classify_diffs_ignores_path_escape(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (tmp_path / "secret.txt").write_text("eval(x)")
    diffs = [FileDiff(path="../secret.txt", status="only_in_package")]
    findings = classify_diffs(diffs, str(tmp_path), str(pkg))
    assert all(f.risk_level == "LOW" or not f.signals for f in findings)


def test_apply_signals_sorts_worst_first(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "a.js").write_text("console.log(1);")
    (pkg / "b.js").write_text('"postinstall": "x"\neval(y);')
    diffs = [
        FileDiff(path="a.js", status="only_in_package"),
        FileDiff(path="b.js", status="only_in_package"),
    ]
    out = apply_signals(classify_diffs(diffs, str(tmp_path), str(pkg)), diffs)
    assert out[0].file_path == "b.js"
