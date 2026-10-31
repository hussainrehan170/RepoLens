"""Command line interface for RepoLens."""

from __future__ import annotations

from pathlib import Path
import typer

from repolens.classify import classify
from repolens.models import DiffStatus, FileDiff, Finding, Report, Risk
from repolens.signals import SIGNAL_WEIGHTS, calculate_score, get_risk_level

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
    package: str = typer.Argument(..., help="Package name"),
    version: str = typer.Argument(..., help="Package version"),
    package_dir: Path | None = typer.Option(
        None,
        "--package-dir",
        "-p",
        help="Path to unpacked package directory.",
    ),
    source_dir: Path | None = typer.Option(
        None,
        "--source-dir",
        "-s",
        help="Path to source repository directory.",
    ),
) -> None:
    """Analyze one package version against its source repository."""
    # Behavior A: No package directory provided
    if package_dir is None:
        typer.echo(f"RepoLens: Analysis requested for {package}@{version}")
        typer.echo("Remote npm registry and repository fetch pipeline is not implemented yet.")
        typer.echo("To analyze a local package archive or directory, use:")
        typer.echo(
            f"  repolens analyze {package} {version} --package-dir <path> [--source-dir <path>]"
        )
        return

    # Behavior B: Validate paths
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

    if source_dir is not None:
        if not source_dir.exists():
            typer.secho(
                f"Error: Source directory does not exist: {source_dir}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        if not source_dir.is_dir():
            typer.secho(
                f"Error: Source path is not a directory: {source_dir}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

    findings, source_found = scan_directory(package_dir, source_dir)

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
        package=package,
        version=version,
        source_found=source_found,
        findings=findings,
        risk=overall_risk,
    )

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


@app.command()
def watch() -> None:
    """Watch a list of packages for new releases."""
    typer.echo("watch: not implemented yet")


if __name__ == "__main__":
    app()
