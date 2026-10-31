"""Classify package/source differences."""

from repolens.models import FileDiff, Finding


def classify(diff: FileDiff) -> Finding:
    """Classify a single file difference using conservative heuristics."""

    path = diff.path.lower()

    # Identical files are expected.
    if diff.status == "identical":
        return Finding(
            path=diff.path,
            label="EXPECTED",
            reason="Package file is identical to source file.",
        )

    # A package manifest difference needs inspection.
    if path.endswith("package.json"):
        return Finding(
            path=diff.path,
            label="UNEXPLAINED",
            reason="Package manifest differs from source.",
        )

    # Build output is only a possible artifact, not automatically trusted.
    if path.startswith("dist/") and path.endswith((".js", ".cjs", ".mjs")):
        return Finding(
            path=diff.path,
            label="UNEXPLAINED",
            reason="JavaScript build output needs source mapping verification.",
        )

    # Source maps may help explain generated files, but need inspection.
    if path.endswith(".map"):
        return Finding(
            path=diff.path,
            label="UNEXPLAINED",
            reason="Source map requires verification against source files.",
        )

    # Unknown differences remain unexplained.
    return Finding(
        path=diff.path,
        label="UNEXPLAINED",
        reason="Difference could not be explained by basic build heuristics.",
    )
