"""Shared data shapes. Everyone codes against these (see team spec)."""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


@dataclass
class FileDiff:
    path: str
    status: str  # 'identical' | 'modified' | 'only_in_package' | 'only_in_source'
    source_sha256: Optional[str] = None
    package_sha256: Optional[str] = None
    diff_text: Optional[str] = None


@dataclass
class Finding:
    file_path: str
    classification: str  # 'EXPECTED' | 'SUSPICIOUS' | 'UNEXPLAINED'
    signals: List[str] = field(default_factory=list)
    risk_level: str = "LOW"  # 'LOW' | 'MEDIUM' | 'HIGH'
    explanation: str = ""
    evidence: str = ""


@dataclass
class Report:
    package_name: str
    version: str
    repo_url: Optional[str]
    commit_or_tag: Optional[str]
    overall_verdict: str  # 'CLEAN' | 'WARNING' | 'SUSPICIOUS'
    overall_risk_score: int  # 0 to 100
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
