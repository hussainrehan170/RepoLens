"""Stage 2: find and shallow-clone the matching source revision. Never crashes."""
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple
from urllib.parse import urlparse

ALLOWED_HOSTS = ("github.com", "gitlab.com")
_STOP_SEGMENTS = {"tree", "blob", "-", "issues", "pulls", "releases", "commit", "commits"}


@dataclass
class SourceResult:
    path: Optional[str] = None          # directory to diff against (None if not found)
    repo_url: Optional[str] = None
    ref: Optional[str] = None           # tag / commit actually used
    note: str = ""                      # human-readable reason when path is None
    tried: List[str] = field(default_factory=list)


def parse_repository(repo_field: Any) -> Tuple[Optional[str], Optional[str]]:
    """npm 'repository' (str or dict) -> (normalized https URL | None, monorepo subdir | None)."""
    directory = None
    raw = repo_field
    if isinstance(repo_field, dict):
        raw = repo_field.get("url")
        directory = repo_field.get("directory")
    if not isinstance(raw, str) or not raw.strip():
        return None, directory
    s = raw.strip().split("#")[0]
    s = re.sub(r"^git\+", "", s)
    m = re.match(r"^(github|gitlab):(.+)$", s)
    if m:
        s = f"https://{m.group(1)}.com/{m.group(2)}"
    m = re.match(r"^git@([^:]+):(.+)$", s)
    if m:
        s = f"https://{m.group(1)}/{m.group(2)}"
    s = re.sub(r"^(ssh://git@|ssh://|git://|http://)", "https://", s)
    if re.match(r"^[\w.-]+/[\w.-]+$", s):  # bare 'user/repo' shorthand = GitHub
        s = f"https://github.com/{s}"
    u = urlparse(s)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        return None, directory
    segs = []
    for seg in [x for x in u.path.split("/") if x]:
        if seg in _STOP_SEGMENTS:
            break
        segs.append(seg)
    if u.hostname == "github.com":
        segs = segs[:2]
    if len(segs) < 2:
        return None, directory
    segs[-1] = re.sub(r"\.git$", "", segs[-1])
    return f"https://{u.hostname}/{'/'.join(segs)}", directory


def _git(args: List[str], cwd: Optional[str] = None, timeout: int = 180) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=timeout)


def _try(args: List[str], cwd: Optional[str] = None) -> bool:
    try:
        return _git(args, cwd=cwd).returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def clone_source(repo_url: Optional[str], name: str, version: str, git_head: Optional[str],
                 workdir: str, directory: Optional[str] = None) -> SourceResult:
    res = SourceResult(repo_url=repo_url)
    if not repo_url:
        res.note = "No usable GitHub/GitLab repository URL in package metadata"
        return res
    if shutil.which("git") is None:
        res.note = "git is not installed"
        return res
    dest = os.path.join(workdir, "source")
    for tag in (f"v{version}", version, f"{name}@{version}"):
        res.tried.append(f"tag:{tag}")
        shutil.rmtree(dest, ignore_errors=True)
        if _try(["clone", "--quiet", "--depth", "1", "--branch", tag, repo_url, dest]):
            res.ref = tag
            break
    else:
        if git_head and re.fullmatch(r"[0-9a-fA-F]{7,40}", git_head):
            res.tried.append(f"gitHead:{git_head}")
            shutil.rmtree(dest, ignore_errors=True)
            os.makedirs(dest, exist_ok=True)
            if (_try(["init", "--quiet", dest]) and _try(["remote", "add", "origin", repo_url], cwd=dest)
                    and _try(["fetch", "--quiet", "--depth", "1", "origin", git_head], cwd=dest)
                    and _try(["checkout", "--quiet", "FETCH_HEAD"], cwd=dest)):
                res.ref = git_head
        if not res.ref:
            shutil.rmtree(dest, ignore_errors=True)
            res.note = f"No matching tag or commit found in {repo_url} (tried: {', '.join(res.tried)})"
            return res
    root = dest
    if directory:  # monorepo sub-package
        cand = os.path.realpath(os.path.join(dest, directory))
        if cand.startswith(os.path.realpath(dest) + os.sep) and os.path.isdir(cand):
            root = cand
    res.path = root
    return res
