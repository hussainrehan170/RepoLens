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


def test_detects_minified_content():
    long_line = "var a = 1; " * 50  # 550 characters on a single line
    signals = inspect_content(long_line)
    assert "minified content" in signals


def test_normal_code_not_minified():
    normal_multiline = "\n".join([f"const line{i} = {i};" for i in range(10)])
    signals = inspect_content(normal_multiline)
    assert "minified content" not in signals


def test_detects_high_entropy_content():
    # Deterministic high-entropy string (103 chars with Shannon entropy ~5.53 > 5.3)
    synthetic_payload = 'const token = "k9J+mZ2L0vQ8xP4rY6tW1sA3uI5oK7hE9gC1fD3bN5mV7xZ9jL0pQ2rS4tU6vW8yA1cE3gI5kM7oQ9sU1wY3aC5eG7iK9mO1qS3uW5y";'
    signals = inspect_content(synthetic_payload)
    assert "high-entropy content" in signals


def test_normal_code_not_high_entropy():
    normal_js = """
    function computeDiscount(cartTotal, isMember) {
        if (isMember) {
            return cartTotal * 0.9;
        }
        return cartTotal;
    }
    """
    signals = inspect_content(normal_js)
    assert "high-entropy content" not in signals


def test_minified_and_high_entropy_weights():
    from repolens.signals import calculate_score

    assert calculate_score(["minified content"]) == 10
    assert calculate_score(["high-entropy content"]) == 25


def test_analyze_content_clean():
    from repolens.signals import analyze_content

    result = analyze_content("const greeting = 'Hello, world!';")
    assert result == {
        "signals": [],
        "score": 0,
        "risk": "LOW",
    }


def test_analyze_content_with_signals():
    from repolens.signals import analyze_content

    # eval (25) + minified line (10) = 35 -> MEDIUM risk
    code = "eval(input);\n" + ("x = 1; " * 80)
    result = analyze_content(code)
    assert "eval usage" in result["signals"]
    assert "minified content" in result["signals"]
    assert result["score"] == 35
    assert result["risk"] == "MEDIUM"


def test_analyze_content_high_risk():
    from repolens.signals import analyze_content

    # lifecycle hook (40) + eval (25) = 65 -> HIGH risk
    package_json_snippet = '"postinstall": "eval(remoteCode)"'
    result = analyze_content(package_json_snippet)
    assert "install lifecycle hook" in result["signals"]
    assert "eval usage" in result["signals"]
    assert result["score"] == 65
    assert result["risk"] == "HIGH"
