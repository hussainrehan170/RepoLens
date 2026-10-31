"""Detect basic risk signals in package files."""

import re


SIGNAL_WEIGHTS = {
    "install lifecycle hook": 40,
    "child_process usage": 25,
    "eval usage": 25,
    "exec usage": 25,
    "network access": 25,
    "environment access": 25,
}


def inspect_content(content: str) -> list[str]:
    """Return risk indicators found in file content."""

    signals = []

    patterns = {
        "child_process usage": r"child_process",
        "eval usage": r"\beval\s*\(",
        "exec usage": r"\bexec\s*\(",
        "network access": r"\bhttps?\.request\b|\bfetch\s*\(",
        "environment access": r"process\.env",
        "install lifecycle hook": (
            r'"(?:preinstall|install|postinstall)"\s*:'
        ),
    }

    for signal, pattern in patterns.items():
        if re.search(pattern, content):
            signals.append(signal)

    return signals


def calculate_score(signals: list[str]) -> int:
    """Calculate a basic weighted risk score."""

    return sum(SIGNAL_WEIGHTS.get(signal, 0) for signal in signals)


def get_risk_level(score: int) -> str:
    """Convert a risk score into a readable risk level."""

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"
