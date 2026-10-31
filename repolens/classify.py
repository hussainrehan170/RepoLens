"""Classify package/source differences."""

from collections.abc import Iterable
import json
import posixpath

from repolens.models import FileDiff, Finding
from repolens.signals import analyze_content

SENSITIVE_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".npmrc",
    ".netrc",
}

FOREIGN_EXEC_EXTENSIONS = (
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".vbs",
    ".ps1",
    ".scr",
)

OUTPUT_PREFIXES = ("dist/", "build/", "lib/", "out/")
OUTPUT_EXTENSIONS = (".js", ".cjs", ".mjs", ".d.ts")
SOURCE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts"]


def find_source_candidate(path: str, known_sources: Iterable[str]) -> str | None:
    """Find a candidate source file in known_sources for a build artifact path.

    Note: The existence of a candidate source does not prove that a package
    artifact was built from it; it only establishes a naming relationship.
    """
    norm = path.replace("\\", "/").lstrip("/")
    norm_lower = norm.lower()

    for prefix in OUTPUT_PREFIXES:
        if norm_lower.startswith(prefix):
            subpath = norm[len(prefix):]
            if subpath.lower().endswith(".d.ts"):
                base = subpath[:-5]
            else:
                base, _ = posixpath.splitext(subpath)

            norm_known = {s.replace("\\", "/").lstrip("/"): s for s in known_sources}
            norm_known_lower = {k.lower(): orig for k, orig in norm_known.items()}

            for candidate in [f"src/{base}{ext}" for ext in SOURCE_EXTENSIONS] + [
                f"{base}{ext}" for ext in SOURCE_EXTENSIONS
            ]:
                if candidate.lower() in norm_known_lower:
                    return norm_known_lower[candidate.lower()]

    return None


def classify(
    diff: FileDiff,
    known_sources: Iterable[str] | None = None,
    content: str | None = None,
) -> Finding:
    """Classify a single file difference using conservative heuristics."""

    norm_path = diff.path.replace("\\", "/").lstrip("/")
    path_lower = norm_path.lower()
    basename = posixpath.basename(norm_path).lower()

    # Step 1: Run static content analysis if content is provided
    signals: list[str] = []
    weight: int = 0
    risk: str = "LOW"
    if content is not None:
        analysis = analyze_content(content)
        signals = analysis["signals"]
        weight = analysis["score"]
        risk = analysis["risk"]

    # Step 2: Identical files are expected
    if diff.status == "identical":
        finding = Finding(
            path=diff.path,
            label="EXPECTED",
            reason="Package file is identical to source file.",
            signals=signals,
            weight=weight,
        )
        if risk == "HIGH":
            finding.label = "SUSPICIOUS"
            finding.reason = f"File contains high-risk indicators: {signals} (score: {weight})."
        return finding

    # Step 3: Package-only sensitive or foreign binary files
    if diff.status == "only_in_package":
        if basename in SENSITIVE_FILENAMES or path_lower.endswith(".aws/credentials"):
            return Finding(
                path=diff.path,
                label="SUSPICIOUS",
                reason="Sensitive credential or configuration file present only in package.",
                signals=signals,
                weight=weight,
            )

        if path_lower.endswith(FOREIGN_EXEC_EXTENSIONS):
            ext = posixpath.splitext(norm_path)[1]
            return Finding(
                path=diff.path,
                label="SUSPICIOUS",
                reason=f"Executable binary or script format ('{ext}') present only in package.",
                signals=signals,
                weight=weight,
            )

    # Step 4: High-risk content escalation
    if risk == "HIGH":
        return Finding(
            path=diff.path,
            label="SUSPICIOUS",
            reason=f"File contains high-risk indicators: {signals} (score: {weight}).",
            signals=signals,
            weight=weight,
        )

    # Step 5: Source map handling
    if path_lower.endswith(".map"):
        if content is not None:
            try:
                data = json.loads(content)
                if not isinstance(data, dict):
                    return Finding(
                        path=diff.path,
                        label="UNEXPLAINED",
                        reason="Malformed source map JSON.",
                        signals=signals,
                        weight=weight,
                    )

                raw_sources = data.get("sources")
                if not raw_sources or not isinstance(raw_sources, list):
                    return Finding(
                        path=diff.path,
                        label="UNEXPLAINED",
                        reason="Source map contains no sources list.",
                        signals=signals,
                        weight=weight,
                    )

                source_root = data.get("sourceRoot") or ""
                map_dir = posixpath.dirname(norm_path)
                norm_sources = {
                    s.replace("\\", "/").lstrip("/").lower()
                    for s in (known_sources or [])
                }

                missing = []
                verified = []
                for src in raw_sources:
                    combined = posixpath.join(map_dir, source_root, src)
                    resolved = posixpath.normpath(combined).lstrip("/")
                    if resolved.lower() in norm_sources:
                        verified.append(resolved)
                    else:
                        missing.append(resolved)

                if missing:
                    return Finding(
                        path=diff.path,
                        label="UNEXPLAINED",
                        reason=f"Source map references sources not found in source repository: {missing}",
                        signals=signals,
                        weight=weight,
                    )

                return Finding(
                    path=diff.path,
                    label="EXPECTED",
                    reason=f"Source map references verified repository sources: {verified}",
                    signals=signals,
                    weight=weight,
                )

            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                return Finding(
                    path=diff.path,
                    label="UNEXPLAINED",
                    reason="Malformed source map JSON.",
                    signals=signals,
                    weight=weight,
                )

        return Finding(
            path=diff.path,
            label="UNEXPLAINED",
            reason="Source map requires verification against source files.",
            signals=signals,
            weight=weight,
        )

    # Step 6: Package manifest difference
    if path_lower.endswith("package.json"):
        reason = "Package manifest differs from source."
        if risk == "MEDIUM":
            reason = f"Package manifest differs from source; contains risk signals: {signals} (score: {weight})."
        return Finding(
            path=diff.path,
            label="UNEXPLAINED",
            reason=reason,
            signals=signals,
            weight=weight,
        )

    # Step 7: Build output matching
    if any(path_lower.startswith(p) for p in OUTPUT_PREFIXES) and path_lower.endswith(OUTPUT_EXTENSIONS):
        if known_sources is not None:
            candidate = find_source_candidate(norm_path, known_sources)
            if candidate:
                return Finding(
                    path=diff.path,
                    label="UNEXPLAINED",
                    reason=f"Candidate source found ('{candidate}'); build relationship not verified.",
                    signals=signals,
                    weight=weight,
                )
            else:
                return Finding(
                    path=diff.path,
                    label="UNEXPLAINED",
                    reason=f"Build output '{diff.path}' has no candidate source file in source repository.",
                    signals=signals,
                    weight=weight,
                )

        reason = "JavaScript build output needs source mapping verification."
        if risk == "MEDIUM":
            reason = f"JavaScript build output contains risk signals: {signals} (score: {weight})."
        return Finding(
            path=diff.path,
            label="UNEXPLAINED",
            reason=reason,
            signals=signals,
            weight=weight,
        )

    # Step 8: Default fallback
    reason = "Difference could not be explained by basic build heuristics."
    if risk == "MEDIUM":
        reason = f"Unexplained file contains risk signals for investigation: {signals} (score: {weight})."

    return Finding(
        path=diff.path,
        label="UNEXPLAINED",
        reason=reason,
        signals=signals,
        weight=weight,
    )
