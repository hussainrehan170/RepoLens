"""Command line interface for RepoLens."""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Optional
import typer

from repolens.classify import classify
from repolens.models import DiffStatus, FileDiff, Finding, Report, Risk
from repolens.signals import SIGNAL_WEIGHTS, calculate_score, get_risk_level

# Attempt to import upstream pipeline if present in repository
try:
    from . import fetch
    from .pipeline import _optional, run_pipeline
    _PIPELINE_AVAILABLE = True
except ImportError:
    fetch = None  # type: ignore
    run_pipeline = None  # type: ignore
    _optional = None  # type: ignore
    _PIPELINE_AVAILABLE = False

app = typer.Typer(help="RepoLens: compare a published package with its source.")


def scan_directory(
    package_dir: Path,
    source_dir: Path | None = None,
) -> tuple[list[Finding], bool]:
    """Scan local package and optional source directory, returning findings and source_found.

    Safely traverses directories without following symlinks outside root directories.
    Handles non-text or binary files safely without crashing.
    """
    source_found = source_dir is not None
    source_files_map: dict[str, Path] = {}

    resolved_pkg_dir = package_dir.resolve()
    resolved_src_dir = source_dir.resolve() if source_dir is not None else None

    if source_dir is not None and resolved_src_dir is not None:
        for p in source_dir.rglob("*"):
            if p.is_file() and not p.is_symlink():
                try:
                    if not p.resolve().is_relative_to(resolved_src_dir):
                        continue
                    rel = p.relative_to(source_dir).as_posix()
                    source_files_map[rel] = p
                except (ValueError, OSError):
                    continue

    package_files_map: dict[str, Path] = {}
    for p in package_dir.rglob("*"):
        if p.is_file() and not p.is_symlink():
            try:
                if not p.resolve().is_relative_to(resolved_pkg_dir):
                    continue
                rel = p.relative_to(package_dir).as_posix()
                package_files_map[rel] = p
            except (ValueError, OSError):
                continue

    findings: list[Finding] = []
    known_sources = list(source_files_map.keys()) if source_found else None

    # Classify each package file against the source tree
    for rel_path, pkg_path in sorted(package_files_map.items()):
        status: DiffStatus = "only_in_package"
        if source_found and rel_path in source_files_map:
            try:
                if pkg_path.read_bytes() == source_files_map[rel_path].read_bytes():
                    status = "identical"
                else:
                    status = "modified"
            except OSError:
                status = "modified"

        # Read static content safely without executing; skip binary decoding safely
        content: str | None = None
        try:
            content = pkg_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            content = None

        diff = FileDiff(path=rel_path, status=status)
        finding = classify(diff, known_sources=known_sources, content=content)
        findings.append(finding)

    return findings, source_found


@app.command()
def analyze(
    package: Optional[str] = typer.Argument(
        None, help="npm package name (optional with --tarball or --package-dir)"
    ),
    version: Optional[str] = typer.Argument(
        None, help="package version (default: latest)"
    ),
    package_dir: Optional[Path] = typer.Option(
        None,
        "--package-dir",
        "-p",
        help="analyze an unpacked local package directory",
    ),
    tarball: Optional[str] = typer.Option(
        None, "--tarball", help="analyze a local .tgz instead of downloading"
    ),
    source_dir: Optional[str] = typer.Option(
        None, "--source-dir", "-s", help="use a local source folder instead of git clone"
    ),
    repo_url: Optional[str] = typer.Option(
        None, "--repo-url", help="override the repository URL"
    ),
    out: str = typer.Option("reports", "--out", help="output directory"),
    keep: bool = typer.Option(False, "--keep", help="keep the temporary sandbox"),
) -> None:
    """Analyze one package version against its source repository."""

    # -------------------------------------------------------------
    # Route 1: Person B local directory analysis (--package-dir)
    # -------------------------------------------------------------
    if package_dir is not None:
        if not package_dir.exists():
            typer.secho(
                f"Error: Package directory does not exist: {package_dir}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        if not package_dir.is_dir():
            typer.secho(
                f"Error: Package path is not a directory: {package_dir}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        src_path_obj: Path | None = None
        if source_dir is not None:
            src_path_obj = Path(source_dir)
            if not src_path_obj.exists():
                typer.secho(
                    f"Error: Source directory does not exist: {source_dir}",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            if not src_path_obj.is_dir():
                typer.secho(
                    f"Error: Source path is not a directory: {source_dir}",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)

        pkg_name = package or package_dir.name or "local-package"
        ver_str = version or "local"

        findings, source_found = scan_directory(package_dir, src_path_obj)

        # Risk aggregation based on unique static signals and file classifications
        unique_signals = sorted(list(set(sig for f in findings for sig in f.signals)))
        signals_score = calculate_score(unique_signals)
        content_risk = get_risk_level(signals_score)
        max_file_score = max((f.weight for f in findings), default=0)

        expected_count = sum(1 for f in findings if f.label == "EXPECTED")
        unexplained_count = sum(1 for f in findings if f.label == "UNEXPLAINED")
        suspicious_count = sum(1 for f in findings if f.label == "SUSPICIOUS")

        # Overall package risk
        if content_risk == "HIGH":
            overall_risk: Risk = "HIGH"
        elif content_risk == "MEDIUM" or suspicious_count > 0:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        report = Report(
            package=pkg_name,
            version=ver_str,
            source_found=source_found,
            findings=findings,
            risk=overall_risk,
        )

        # Write reports to output directory if specified
        os.makedirs(out, exist_ok=True)
        report_file = os.path.join(out, "report.json")
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(report), f, indent=2)

        # Format readable output for terminal
        typer.echo("=" * 60)
        typer.echo(f"RepoLens Analysis Report: {report.package}@{report.version}")
        typer.echo("=" * 60)
        typer.echo(f"Package directory   : {package_dir}")
        if source_found:
            typer.echo(f"Source directory    : {source_dir}")
            typer.echo("Source verification : Compared against local source repository")
        else:
            typer.echo("Source verification : No source repository provided (unverified)")

        typer.echo(f"Overall Risk Level  : {report.risk}")
        typer.echo(f"  - Content Risk    : {content_risk} (Score: {signals_score} from unique signals)")
        typer.echo(f"  - Max File Score  : {max_file_score}")
        typer.echo(f"  - Suspicious Files: {suspicious_count}")

        typer.echo("\nClassification Summary:")
        typer.echo(f"  EXPECTED    : {expected_count}")
        typer.echo(f"  UNEXPLAINED : {unexplained_count}")
        typer.echo(f"  SUSPICIOUS  : {suspicious_count}")

        if unique_signals:
            typer.echo("\nStatic Indicators Detected (evidence for investigation):")
            for sig in unique_signals:
                w = SIGNAL_WEIGHTS.get(sig, 0)
                typer.echo(f"  - {sig} (weight: {w})")

        investigation_findings = [f for f in findings if f.label in ("SUSPICIOUS", "UNEXPLAINED")]
        if investigation_findings:
            typer.echo("\nFindings for Investigation:")
            for f in investigation_findings:
                typer.echo(f"  [{f.label}] {f.path}")
                typer.echo(f"    Reason : {f.reason}")
                if f.signals:
                    typer.echo(f"    Signals: {f.signals} (weight: {f.weight})")

        typer.echo("=" * 60)
        return

    # -------------------------------------------------------------
    # Route 2: Upstream remote fetch & pipeline orchestration
    # -------------------------------------------------------------
    if _PIPELINE_AVAILABLE and run_pipeline is not None and fetch is not None:
        if not package and not tarball:
            typer.echo("[repolens] ERROR: Please provide a package name, --tarball, or --package-dir.", err=True)
            raise typer.Exit(code=1)

        workdir = tempfile.mkdtemp(prefix="repolens_")
        try:
            pipeline_report = run_pipeline(package, version, workdir, tarball, source_dir, repo_url)
        except fetch.FetchError as e:
            typer.echo(f"[repolens] ERROR: {e}", err=True)
            raise typer.Exit(code=1)
        finally:
            if not keep:
                shutil.rmtree(workdir, ignore_errors=True)

        os.makedirs(out, exist_ok=True)
        report_mod = _optional("report") if _optional else None
        if report_mod and hasattr(report_mod, "write_reports"):
            report_mod.write_reports(pipeline_report, out)
        else:
            with open(os.path.join(out, "report.json"), "w", encoding="utf-8") as f:
                json.dump(dataclasses.asdict(pipeline_report), f, indent=2)

        c = pipeline_report.metadata.get("file_counts", {})
        typer.echo(
            f"[repolens] {pipeline_report.package_name}@{pipeline_report.version}  "
            f"source ref: {pipeline_report.commit_or_tag or 'NOT FOUND'}"
        )
        if c:
            typer.echo(
                f"[repolens] files: {c.get('identical', 0)} identical, {c.get('modified', 0)} modified, "
                f"{c.get('only_in_package', 0)} only-in-package, {c.get('only_in_source', 0)} only-in-source"
            )
        for fd in pipeline_report.findings[:30]:
            sig_str = ",".join(getattr(fd, "signals", []))
            r_level = getattr(fd, "risk_level", "LOW")
            c_label = getattr(fd, "classification", "UNEXPLAINED")
            f_path = getattr(fd, "file_path", getattr(fd, "path", ""))
            typer.echo(f"  [{r_level:6}] {c_label:11} {f_path}  {sig_str}")
        if len(pipeline_report.findings) > 30:
            typer.echo(f"  ... and {len(pipeline_report.findings) - 30} more (see report.json)")

        typer.echo(
            f"[repolens] VERDICT: {pipeline_report.overall_verdict} "
            f"(risk {pipeline_report.overall_risk_score}/100) -> {out}/"
        )
        if pipeline_report.overall_verdict == "SUSPICIOUS":
            raise typer.Exit(code=2)
        return

    # -------------------------------------------------------------
    # Fallback: Pipeline module not available in this environment
    # -------------------------------------------------------------
    pkg_disp = package or "package"
    ver_disp = version or "version"
    typer.echo(f"RepoLens: Analysis requested for {pkg_disp}@{ver_disp}")
    typer.echo("Remote npm registry and repository fetch pipeline is not implemented yet.")
    typer.echo("To analyze a local package archive or directory, use:")
    typer.echo(
        f"  repolens analyze {pkg_disp} {ver_disp} --package-dir <path> [--source-dir <path>]"
    )


@app.command()
def watch() -> None:
    """Watch a list of packages for new releases."""
    typer.echo("watch: not implemented yet")


if __name__ == "__main__":
    app()
