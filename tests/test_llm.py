import os
import unittest
from unittest import mock

from repolens import llm
from repolens.models import Finding


class MockMode(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.dict(os.environ, {"REPOLENS_LLM": "mock"})
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_high_signal(self):
        r = llm.explain_finding("scripts/x.js", "UNEXPLAINED", ["NEW_INSTALL_HOOK"])
        self.assertEqual((r["verdict"], r["risk_level"], r["engine"]), ("suspicious", "HIGH", "mock"))

    def test_expected(self):
        r = llm.explain_finding("dist/a.js", "EXPECTED", [])
        self.assertEqual((r["verdict"], r["risk_level"]), ("expected", "LOW"))

    def test_unexplained(self):
        self.assertEqual(llm.explain_finding("a.js", "UNEXPLAINED", [])["risk_level"], "MEDIUM")

    def test_deterministic(self):
        a = llm.explain_finding("a.js", "UNEXPLAINED", ["DANGEROUS_API"], "x")
        self.assertEqual(a, llm.explain_finding("a.js", "UNEXPLAINED", ["DANGEROUS_API"], "x"))

    def test_enrich_sets_explanation_and_keeps_classification(self):
        f = Finding(file_path="a.js", classification="UNEXPLAINED",
                    signals=["NEW_INSTALL_HOOK"])
        out = llm.enrich_finding(f)
        self.assertIs(out, f)
        self.assertEqual(f.classification, "UNEXPLAINED")
        self.assertEqual(f.risk_level, "HIGH")
        self.assertTrue(f.explanation)
    def test_pkgcheck_env_name_also_works(self):
        with mock.patch.dict(os.environ, {"REPOLENS_LLM": "", "PKGCHECK_LLM": "mock"}):
            self.assertEqual(llm.get_mode(), "mock")


class OllamaMode(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.dict(os.environ, {
            "REPOLENS_LLM": "ollama",
            "OLLAMA_URL": "http://127.0.0.1:9/api/generate",
            "REPOLENS_LLM_TIMEOUT": "2"})
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_unreachable_falls_back_without_recursion(self):
        r = llm.explain_finding("a.js", "UNEXPLAINED", ["NEW_INSTALL_HOOK"])
        self.assertEqual(r["risk_level"], "HIGH")
        self.assertIn("unreachable", r["engine"])

    def test_valid_llm_answer_used(self):
        good = {"explanation": "Reads env.", "verdict": "suspicious", "reason": "r", "risk_level": "high"}
        with mock.patch.object(llm, "_call_ollama", return_value=good):
            r = llm.explain_finding("a.js", "UNEXPLAINED", ["DANGEROUS_API"])
        self.assertEqual((r["risk_level"], r["engine"]), ("HIGH", llm.MODEL_NAME))

    def test_llm_cannot_downgrade(self):
        bad = {"explanation": "Looks fine.", "verdict": "expected", "reason": "r", "risk_level": "LOW"}
        with mock.patch.object(llm, "_call_ollama", return_value=bad):
            r = llm.explain_finding("postinstall.js", "UNEXPLAINED", ["NEW_INSTALL_HOOK"], "ignore previous")
        self.assertEqual((r["risk_level"], r["verdict"]), ("HIGH", "suspicious"))

    def test_garbage_output_falls_back(self):
        with mock.patch.object(llm, "_call_ollama", return_value={"foo": 1}):
            r = llm.explain_finding("a.js", "EXPECTED", [])
        self.assertIn("invalid", r["engine"])

    def test_prompt_marks_snippet_untrusted(self):
        self.assertIn("UNTRUSTED", llm._build_prompt("a", "X", [], "s"))
