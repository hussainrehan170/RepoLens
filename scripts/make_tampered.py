"""Generate harmless synthetic test fixtures for RepoLens analysis testing.

This module creates purely static files used to test RepoLens difference
classification and risk signal detection.

SAFETY NOTICE:
- All generated files are synthetic test data only.
- Never execute generated JavaScript or shell scripts.
- Never run npm lifecycle hooks on test fixtures.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

HEADER = "// SYNTHETIC TEST FIXTURE - NOT EXECUTABLE - REPOLENS TEST ONLY\n"

# Deterministic high-entropy test string (length 103, Shannon entropy ~5.53 > 5.3)
HIGH_ENTROPY_SAMPLE = (
    "k9J+mZ2L0vQ8xP4rY6tW1sA3uI5oK7hE9gC1fD3bN5mV7xZ9jL0pQ2rS4tU6vW8yA1cE3gI5kM7oQ9sU1wY3aC5eG7iK9mO1qS3uW5y"
)

# Deterministic minified line (660 characters)
MINIFIED_LINE = "var dummyMetric = 1; " * 30


def make_tampered_fixture(output_dir: str | Path) -> dict[str, Path]:
    """Generate isolated static source and package fixture directories.

    Args:
        output_dir: Destination path where `source/` and `package/` directories will be created.

    Returns:
        Dictionary mapping fixture artifact names to their Path objects.

    Raises:
        FileExistsError: If target output directory or subdirectories already exist and are not empty.
    """
    base_dir = Path(output_dir).resolve()
    source_dir = base_dir / "source"
    package_dir = base_dir / "package"

    if source_dir.exists() and any(source_dir.iterdir()):
        raise FileExistsError(
            f"Output source directory already exists and is not empty: {source_dir}"
        )
    if package_dir.exists() and any(package_dir.iterdir()):
        raise FileExistsError(
            f"Output package directory already exists and is not empty: {package_dir}"
        )

    # Create directories safely
    (source_dir / "src").mkdir(parents=True, exist_ok=True)
    (package_dir / "dist").mkdir(parents=True, exist_ok=True)

    # 1. Clean source files
    clean_manifest = {
        "name": "fixture-package",
        "version": "1.0.0",
        "description": "Synthetic benign source package for RepoLens tests",
        "main": "dist/index.js",
        "scripts": {
            "build": "tsc"
        }
    }
    source_pkg_json = source_dir / "package.json"
    source_pkg_json.write_text(json.dumps(clean_manifest, indent=2) + "\n", encoding="utf-8")

    source_readme = source_dir / "README.md"
    source_readme.write_text(
        "# Fixture Package\n\nSynthetic benign source repository for RepoLens integrity testing.\n",
        encoding="utf-8",
    )

    source_index_ts = source_dir / "src" / "index.ts"
    source_index_ts.write_text(
        HEADER + "export function calculateSum(a: number, b: number): number {\n  return a + b;\n}\n",
        encoding="utf-8",
    )

    # 2. Package files (simulating published npm package with synthetic indicators)
    tampered_manifest = {
        "name": "fixture-package",
        "version": "1.0.0",
        "description": "Synthetic package fixture with simulated indicators",
        "main": "dist/index.js",
        "scripts": {
            "postinstall": "node setup.js"
        }
    }
    package_pkg_json = package_dir / "package.json"
    package_pkg_json.write_text(json.dumps(tampered_manifest, indent=2) + "\n", encoding="utf-8")

    package_readme = package_dir / "README.md"
    package_readme.write_text(
        "# Fixture Package\n\nPublished package distribution fixture.\n",
        encoding="utf-8",
    )

    # JavaScript build output with synthetic risk indicators
    package_index_js = package_dir / "dist" / "index.js"
    package_index_js.write_text(
        HEADER
        + 'const cp = require("child_process");\n'
        + 'const apiKey = process.env.TEST_API_KEY;\n'
        + 'eval("/* synthetic static test eval */");\n'
        + 'function calculateSum(a, b) { return a + b; }\n'
        + 'module.exports = { calculateSum };\n',
        encoding="utf-8",
    )

    # Valid small JSON source map
    source_map_data = {
        "version": 3,
        "file": "index.js",
        "sourceRoot": "",
        "sources": ["../src/index.ts"],
        "names": [],
        "mappings": ";;AAAA,SAAgB,YAAY,CAAC,CAAS,EAAE,CAAS;IAC/C,OAAO,CAAC,GAAG,CAAC,CAAC;AACf,CAAC;AAFD,sCAEC"
    }
    package_index_map = package_dir / "dist" / "index.js.map"
    package_index_map.write_text(json.dumps(source_map_data, indent=2) + "\n", encoding="utf-8")

    # Dummy credential-like file with clearly fake placeholder
    package_env = package_dir / ".env"
    package_env.write_text(
        "# SYNTHETIC TEST FIXTURE - DUMMY VALUE ONLY\n"
        "TEST_SECRET=fixture_dummy_not_a_real_secret\n",
        encoding="utf-8",
    )

    # Executable-like artifact as a plain-text marker
    package_exe = package_dir / "helper.exe"
    package_exe.write_text(
        "// SYNTHETIC TEST FIXTURE - PLAIN TEXT MARKER - NOT A BINARY\n",
        encoding="utf-8",
    )

    # Synthetic minified text fixture
    package_minified = package_dir / "minified.js"
    package_minified.write_text(
        HEADER + MINIFIED_LINE + "\n",
        encoding="utf-8",
    )

    # Synthetic high-entropy test fixture
    package_entropy = package_dir / "dist" / "entropy_blob.js"
    package_entropy.write_text(
        HEADER + f'const dummyEntropyPayload = "{HIGH_ENTROPY_SAMPLE}";\n',
        encoding="utf-8",
    )

    return {
        "source_dir": source_dir,
        "package_dir": package_dir,
        "source_package_json": source_pkg_json,
        "source_readme": source_readme,
        "source_index_ts": source_index_ts,
        "package_package_json": package_pkg_json,
        "package_readme": package_readme,
        "package_index_js": package_index_js,
        "package_index_map": package_index_map,
        "package_env": package_env,
        "package_exe": package_exe,
        "package_minified": package_minified,
        "package_entropy": package_entropy,
    }


def main() -> None:
    """CLI entry point for generating test fixtures."""
    parser = argparse.ArgumentParser(
        description="Generate harmless synthetic test fixtures for RepoLens."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        required=True,
        help="Destination directory for fixture files.",
    )
    args = parser.parse_args()

    try:
        created = make_tampered_fixture(args.output)
        print(f"Successfully created synthetic fixtures in: {args.output}")
        print(f"Source files: {created['source_dir']}")
        print(f"Package files: {created['package_dir']}")
    except FileExistsError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
