import subprocess

import pytest

from repolens import source


@pytest.mark.parametrize("raw,expected", [
    ("git+https://github.com/lodash/lodash.git", "https://github.com/lodash/lodash"),
    ({"type": "git", "url": "git@github.com:a/b.git", "directory": "packages/x"}, "https://github.com/a/b"),
    ("github:a/b", "https://github.com/a/b"),
    ("a/b", "https://github.com/a/b"),
    ("https://github.com/a/b/tree/main/pkg", "https://github.com/a/b"),
    ("https://gitlab.com/g/sub/r.git", "https://gitlab.com/g/sub/r"),
    ("https://evil.example.com/a/b", None),
    ("file:///etc/passwd", None),
    (None, None),
])
def test_parse_repository(raw, expected):
    assert source.parse_repository(raw)[0] == expected


def test_parse_repository_directory():
    assert source.parse_repository({"url": "github:a/b", "directory": "packages/x"})[1] == "packages/x"


def test_no_repo_url_does_not_crash(tmp_path):
    r = source.clone_source(None, "x", "1.0.0", None, str(tmp_path))
    assert r.path is None and "No usable" in r.note


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   cwd=cwd, check=True, capture_output=True)


def test_clone_by_tag_and_missing_tag(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "index.js").write_text("1")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "init")
    _git(repo, "tag", "v1.0.0")
    url = f"file://{repo}"
    ok = source.clone_source(url, "x", "1.0.0", None, str(tmp_path / "w1"))
    assert ok.ref == "v1.0.0" and (tmp_path / "w1" / "source" / "index.js").exists()
    missing = source.clone_source(url, "x", "9.9.9", None, str(tmp_path / "w2"))
    assert missing.path is None and "No matching tag" in missing.note
