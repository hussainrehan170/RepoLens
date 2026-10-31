"""Stage 3: hash + compare the package dir against the source dir (static only)."""
import difflib
import hashlib
import os
from typing import Dict, List, Optional

from .models import FileDiff

IGNORE_DIRS = {".git", "node_modules", ".github", ".circleci", ".gitlab", ".travis", ".husky", ".idea", ".vscode"}
MAX_DIFF_CHARS = 20000
MAX_READ_BYTES = 2 * 1024 * 1024


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk(root: str) -> Dict[str, str]:
    files: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            files[os.path.relpath(full, root).replace(os.sep, "/")] = full
    return files


def _read_text(path: str) -> Optional[str]:
    """Return file text, or None if it looks binary. Capped to keep reports small."""
    with open(path, "rb") as f:
        data = f.read(MAX_READ_BYTES)
    if b"\x00" in data:
        return None
    return data.decode("utf-8", errors="replace")


def _make_diff(src: Optional[str], pkg: Optional[str], path: str) -> Optional[str]:
    if pkg is None:
        return None
    if src is None:  # only in package: expose content so signals.py can scan it
        return pkg[:MAX_DIFF_CHARS]
    lines = difflib.unified_diff(src.splitlines(), pkg.splitlines(),
                                 f"source/{path}", f"package/{path}", lineterm="", n=2)
    return "\n".join(lines)[:MAX_DIFF_CHARS]


def compare_dirs(source_dir: Optional[str], package_dir: str) -> List[FileDiff]:
    src_files = _walk(source_dir) if source_dir else {}
    pkg_files = _walk(package_dir)
    out: List[FileDiff] = []
    for path in sorted(set(src_files) | set(pkg_files)):
        s, p = src_files.get(path), pkg_files.get(path)
        s_hash = sha256_file(s) if s else None
        p_hash = sha256_file(p) if p else None
        if s and p:
            status = "identical" if s_hash == p_hash else "modified"
        elif p:
            status = "only_in_package"
        else:
            status = "only_in_source"
        text = None
        if status in ("modified", "only_in_package"):
            text = _make_diff(_read_text(s) if s else None, _read_text(p), path)
        out.append(FileDiff(path=path, status=status, source_sha256=s_hash,
                            package_sha256=p_hash, diff_text=text))
    return out
