"""Tests for risk signal detection."""

from repolens.signals import inspect_content


def test_detects_eval():
    signals = inspect_content("eval(user_input)")
    assert "eval usage" in signals


def test_detects_network_access():
    signals = inspect_content("fetch(url)")
    assert "network access" in signals


def test_detects_environment_access():
    signals = inspect_content("process.env")
    assert "environment access" in signals


def test_clean_content_has_no_signals():
    signals = inspect_content("def add(a, b): return a + b")
    assert signals == []


def test_detects_install_lifecycle_hook():
    signals = inspect_content('"postinstall": "node setup.js"')
    assert "install lifecycle hook" in signals


def test_lifecycle_hook_score():
    from repolens.signals import calculate_score

    assert calculate_score(["install lifecycle hook"]) == 40


def test_dangerous_api_score():
    from repolens.signals import calculate_score

    assert calculate_score(["eval usage"]) == 25


def test_multiple_signals_score():
    from repolens.signals import calculate_score

    signals = ["install lifecycle hook", "eval usage"]

    assert calculate_score(signals) == 65


def test_low_risk_level():
    from repolens.signals import get_risk_level

    assert get_risk_level(10) == "LOW"


def test_medium_risk_level():
    from repolens.signals import get_risk_level

    assert get_risk_level(25) == "MEDIUM"


def test_high_risk_level():
    from repolens.signals import get_risk_level

    assert get_risk_level(65) == "HIGH"

