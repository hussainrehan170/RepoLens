"""Stage 1: get the published npm package onto disk. NOTHING is ever executed."""
import base64
import hashlib
import json
import os
import ssl
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

REGISTRY = "https://registry.npmjs.org"
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
USER_AGENT = "repolens/0.1 (hackathon supply-chain auditor)"


class FetchError(Exception):
    pass


def _ssl_context() -> ssl.SSLContext:
    """Use certifi's CA bundle when available (fixes macOS python.org builds)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _http_get(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout, context=_ssl_context())


def get_metadata(package: str, version: str = "latest") -> Dict[str, Any]:
    """Fetch https://registry.npmjs.org/<pkg>/<version> (scoped names are escaped)."""
    url = f"{REGISTRY}/{urllib.parse.quote(package, safe='@')}/{urllib.parse.quote(version)}"
    try:
        with _http_get(url) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise FetchError(f"Registry returned HTTP {e.code} for {package}@{version}") from e
    except Exception as e:
        raise FetchError(f"Could not reach registry for {package}@{version}: {e}") from e


def download_tarball(url: str, dest_file: str, integrity: Optional[str] = None) -> None:
    """Stream the tarball to disk (size capped) and verify npm's sha512 integrity if given."""
    sha512 = hashlib.sha512()
    total = 0
    try:
        with _http_get(url, timeout=60) as r, open(dest_file, "wb") as out:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise FetchError("Tarball exceeds size limit")
                sha512.update(chunk)
                out.write(chunk)
    except FetchError:
        raise
    except Exception as e:
        raise FetchError(f"Tarball download failed: {e}") from e
    if integrity and integrity.startswith("sha512-"):
        got = "sha512-" + base64.b64encode(sha512.digest()).decode()
        if got != integrity:
            raise FetchError("Tarball integrity mismatch vs registry metadata")


def safe_extract(tar_path: str, dest: str) -> List[str]:
    """Extract file contents only (no perms, no links, no devices) with the leading
    'package/' folder stripped. Returns names of skipped special members."""
    os.makedirs(dest, exist_ok=True)
    dest = os.path.realpath(dest)
    skipped: List[str] = []
    total = 0
    try:
        tf = tarfile.open(tar_path, "r:*")
    except Exception as e:
        raise FetchError(f"Not a valid tarball: {e}") from e
    with tf:
        members = tf.getmembers()

        def parts_of(m):
            return [p for p in m.name.replace("\\", "/").split("/") if p not in ("", ".")]

        firsts = {parts_of(m)[0] for m in members if parts_of(m)}
        strip = 1 if len(firsts) == 1 and all(len(parts_of(m)) >= 1 for m in members) else 0
        if strip and len(members) == 1 and members[0].isfile():
            strip = 0
        for m in members:
            parts = parts_of(m)[strip:]
            if not parts:
                continue
            if ".." in parts:
                raise FetchError(f"Path traversal attempt in tarball: {m.name}")
            target = os.path.realpath(os.path.join(dest, *parts))
            if not target.startswith(dest + os.sep):
                raise FetchError(f"Unsafe path in tarball: {m.name}")
            if m.isdir():
                os.makedirs(target, exist_ok=True)
            elif m.isfile():
                total += m.size
                if total > MAX_EXTRACTED_BYTES:
                    raise FetchError("Extracted size exceeds limit")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                src = tf.extractfile(m)
                with open(target, "wb") as out:
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        out.write(chunk)
            else:
                skipped.append(m.name)  # symlink / hardlink / device: never created
    return skipped


def fetch_package(package: Optional[str], version: Optional[str], workdir: str,
                  tarball: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    """Returns (extracted_package_dir, metadata). Metadata keys: name, version,
    repository, gitHead, tarball_url, integrity, skipped_members."""
    pkg_dir = os.path.join(workdir, "package")
    meta: Dict[str, Any] = {}
    if tarball:
        if not os.path.isfile(tarball):
            raise FetchError(f"Tarball not found: {tarball}")
        skipped = safe_extract(tarball, pkg_dir)
        pj = os.path.join(pkg_dir, "package.json")
        if os.path.isfile(pj):
            try:
                with open(pj, encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                meta = {}
        meta["tarball_url"] = os.path.abspath(tarball)
    else:
        if not package:
            raise FetchError("Package name required when --tarball is not given")
        meta = get_metadata(package, version or "latest")
        dist = meta.get("dist") or {}
        if not dist.get("tarball"):
            raise FetchError("Registry metadata has no tarball URL")
        tgz = os.path.join(workdir, "pkg.tgz")
        download_tarball(dist["tarball"], tgz, dist.get("integrity"))
        skipped = safe_extract(tgz, pkg_dir)
        meta["tarball_url"] = dist["tarball"]
        meta["integrity"] = dist.get("integrity")
    meta["skipped_members"] = skipped
    return pkg_dir, meta
