# RepoLens

Compare a **published package** (npm) with its **source repository**, explain every
difference, and flag suspicious releases. Built for Hacktoberfest Hack Day Sonipat
(Problem 4: Published Package vs Source Code Integrity Analyzer).

## Install

```
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```
repolens analyze <package> <version>
repolens watch
```

## Run tests

```
pytest
```

## Status

Skeleton only. Features are being added through pull requests.

## License

Apache-2.0
