"""Detect basic risk signals in package files."""

from collections import Counter
import math
import re


SIGNAL_WEIGHTS = {
    "install lifecycle hook": 40,
    "child_process usage": 25,
    "eval usage": 25,
    "exec usage": 25,
    "network access": 25,
    "environment access": 25,
    "high-entropy content": 25,
    "minified content": 10,
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a string using standard library math."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def has_high_entropy(content: str, threshold: float = 5.3, min_length: int = 100) -> bool:
    """Check if content has contiguous tokens of high Shannon entropy.

    This serves as a static heuristic to flag potential encrypted/packed blobs
    or obfuscated strings for further investigation. It is not proof of malware.
    """
    tokens = re.findall(r"\S+", content)
    for token in tokens:
        cleaned = token.strip("\"'`();,")
        if len(cleaned) >= min_length:
            if calculate_shannon_entropy(cleaned) >= threshold:
                return True
    return False


def is_minified(content: str, max_line_length: int = 500) -> bool:
    """Return True if content contains any line exceeding max_line_length characters.

    Note: Minified code is common and standard in npm packages; it is a signal
    for investigation, not proof of malicious intent.
    """
    for line in content.splitlines():
        if len(line) >= max_line_length:
            return True
    return False


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

    if has_high_entropy(content):
        signals.append("high-entropy content")

    if is_minified(content):
        signals.append("minified content")

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


def analyze_content(content: str) -> dict:
    """Analyze file content and return detected signals, total score, and risk level."""
    signals = inspect_content(content)
    score = calculate_score(signals)
    risk = get_risk_level(score)

    return {
        "signals": signals,
        "score": score,
        "risk": risk,
    }


def apply_signals(findings, diffs=None):
    """Final pass: HIGH risk is always SUSPICIOUS, and the worst findings come first."""
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for f in findings:
        if f.risk_level == "HIGH":
            f.classification = "SUSPICIOUS"
    return sorted(findings, key=lambda f: (order.get(f.risk_level, 3), f.file_path))
