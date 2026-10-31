"""Pipeline orchestration (no CLI code here, so it is easy to test).

Stages: 1 fetch -> 2 source -> 3 diff -> 4 classify + signals (Person B)
        -> 5 explain (Person C llm) -> verdict. Person B/C modules are optional at
import time so the pipeline works end-to-end from day one.
"""
import importlib
from typing import List, Optional

from . import diff as diffmod
from . import fetch, source
from .models import FileDiff, Finding, Report

RISK_POINTS = {"HIGH": 40, "MEDIUM": 15, "LOW": 0}


def _optional(name: str):
    try:
        return importlib.import_module(f"repolens.{name}")
    except ImportError:
        return None


def _fallback_classify(diffs: List[FileDiff]) -> List[Finding]:
    """Used until Person B's classify.py exists: every difference is UNEXPLAINED."""
    out = []
    for d in diffs:
        if d.status in ("modified", "only_in_package"):
            out.append(Finding(file_path=d.path, classification="UNEXPLAINED", risk_level="MEDIUM",
                               explanation=f"File is {d.status.replace('_', ' ')} (no classifier loaded).",
                               evidence=(d.diff_text or "")[:500]))
    return out


def compute_verdict(findings: List[Finding]):
    """SUSPICIOUS needs at least one HIGH finding; many MEDIUM findings only ever give WARNING."""
    active = [f for f in findings if f.classification != "EXPECTED"]
    high = sum(1 for f in active if f.risk_level == "HIGH")
    medium = sum(1 for f in active if f.risk_level == "MEDIUM")
    score = min(100, 40 * high + min(30, 10 * medium))
    if high or score >= 60:
        return "SUSPICIOUS", score
    if medium:
        return "WARNING", score
    return "CLEAN", score


def run_pipeline(package: Optional[str], version: Optional[str], workdir: str,
                 tarball: Optional[str] = None, source_dir: Optional[str] = None,
                 repo_url: Optional[str] = None) -> Report:
    # Stage 1: fetch
    pkg_dir, meta = fetch.fetch_package(package, version, workdir, tarball)
    name = meta.get("name") or package or "unknown"
    ver = meta.get("version") or version or "unknown"
    findings: List[Finding] = []
    notes: List[str] = []

    # Stage 2: source
    if source_dir:
        src = source.SourceResult(path=source_dir, repo_url=repo_url, ref="local-dir")
    else:
        url, subdir = source.parse_repository(repo_url or meta.get("repository"))
        src = source.clone_source(url, name, ver, meta.get("gitHead"), workdir, subdir)
    if not src.path:
        notes.append(src.note)
        findings.append(Finding(file_path="<repository>", classification="UNEXPLAINED", risk_level="MEDIUM",
                                signals=["SOURCE_NOT_FOUND"],
                                explanation="Could not locate matching source for this version, so the "
                                            "package cannot be verified against source.",
                                evidence=src.note))

    # Stage 3: diff
    diffs = diffmod.compare_dirs(src.path, pkg_dir)
    counts = {s: sum(1 for d in diffs if d.status == s)
              for s in ("identical", "modified", "only_in_package", "only_in_source")}

    # Stage 4: classify + signals (Person B)
    classify, signals = _optional("classify"), _optional("signals")
    if src.path:
        if classify and hasattr(classify, "classify_diffs"):
            findings += classify.classify_diffs(diffs, src.path, pkg_dir)
        else:
            findings += _fallback_classify(diffs)
    else:  # no source: surface only the interesting package files
        interesting = [d for d in diffs if d.path.endswith((".json", ".sh", ".js", ".cjs", ".mjs"))][:50]
        findings += _fallback_classify(interesting)
    if signals and hasattr(signals, "apply_signals"):
        findings = signals.apply_signals(findings, diffs)

    # Stage 5: explanations (Person C)
    llm = _optional("llm")
    if llm and hasattr(llm, "explain_finding"):
        for f in findings:
            try:
                r = llm.explain_finding(f.file_path, f.classification, f.signals, f.evidence)
                f.explanation = r.get("explanation") or f.explanation
                if r.get("risk_level") in ("LOW", "MEDIUM", "HIGH") and f.risk_level != "HIGH":
                    f.risk_level = r["risk_level"]
            except Exception as e:  # the LLM must never kill the pipeline
                notes.append(f"LLM explain failed for {f.file_path}: {e}")

    verdict, score = compute_verdict(findings)
    return Report(package_name=name, version=ver, repo_url=src.repo_url, commit_or_tag=src.ref,
                  overall_verdict=verdict, overall_risk_score=score, findings=findings,
                  metadata={"file_counts": counts, "notes": notes, "source_tried": src.tried,
                            "skipped_tar_members": meta.get("skipped_members", []),
                            "tarball": meta.get("tarball_url")})
