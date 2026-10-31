"""Command line interface for RepoLens."""
import typer

app = typer.Typer(help="RepoLens: compare a published package with its source.")


@app.command()
def analyze(package: str, version: str) -> None:
    """Analyze one package version against its source repository."""
    typer.echo(f"analyze {package}@{version}: not implemented yet")


@app.command()
def watch() -> None:
    """Watch a list of packages for new releases."""
    typer.echo("watch: not implemented yet")


if __name__ == "__main__":
    app()
