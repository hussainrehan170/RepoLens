import io
import tarfile

import pytest

from repolens import fetch


def make_tgz(path, files, prefix="package/"):
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            ti = tarfile.TarInfo(prefix + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))


def test_strip_prefix_and_extract(tmp_path):
    t = tmp_path / "a.tgz"
    make_tgz(t, {"package.json": "{}", "dist/index.js": "x"})
    fetch.safe_extract(str(t), str(tmp_path / "out"))
    assert (tmp_path / "out" / "dist" / "index.js").exists()
    assert (tmp_path / "out" / "package.json").exists()


def test_path_traversal_blocked(tmp_path):
    t = tmp_path / "evil.tgz"
    make_tgz(t, {"../../evil.txt": "x"})
    with pytest.raises(fetch.FetchError):
        fetch.safe_extract(str(t), str(tmp_path / "out"))


def test_symlink_skipped(tmp_path):
    t = tmp_path / "s.tgz"
    with tarfile.open(t, "w:gz") as tf:
        ti = tarfile.TarInfo("package/link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)
        ti2 = tarfile.TarInfo("package/package.json")
        ti2.size = 2
        tf.addfile(ti2, io.BytesIO(b"{}"))
    skipped = fetch.safe_extract(str(t), str(tmp_path / "out"))
    assert skipped == ["package/link"]
    assert not (tmp_path / "out" / "link").exists()
