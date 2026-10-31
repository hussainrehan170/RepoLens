from repolens import diff


def test_compare_dirs(tmp_path):
    s, p = tmp_path / "s", tmp_path / "p"
    for d in (s, p):
        d.mkdir()
    (s / "a.js").write_text("1\n")
    (p / "a.js").write_text("1\n")
    (s / "b.js").write_text("1\n")
    (p / "b.js").write_text("2\n")
    (s / "only_src.ts").write_text("x")
    (p / "evil.js").write_text("eval(1)")
    (s / "node_modules").mkdir()
    (s / "node_modules" / "z.js").write_text("z")
    r = {d.path: d for d in diff.compare_dirs(str(s), str(p))}
    assert r["a.js"].status == "identical"
    assert r["b.js"].status == "modified" and "+2" in r["b.js"].diff_text
    assert r["evil.js"].status == "only_in_package" and "eval" in r["evil.js"].diff_text
    assert r["only_src.ts"].status == "only_in_source"
    assert "node_modules/z.js" not in r


def test_no_source_means_all_only_in_package(tmp_path):
    p = tmp_path / "p"
    p.mkdir()
    (p / "x.js").write_text("1")
    r = diff.compare_dirs(None, str(p))
    assert [d.status for d in r] == ["only_in_package"]
