"""Shared data shapes. Everyone codes against these (see team spec)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

DiffStatus = Literal["identical", "modified", "only_in_package", "only_in_source"]
Label = Literal["EXPECTED", "SUSPICIOUS", "UNEXPLAINED"]
Risk = Literal["LOW", "MEDIUM", "HIGH"]


@dataclass
class FileDiff:
    path: str
    status: str  # 'identical' | 'modified' | 'only_in_package' | 'only_in_source'
    source_sha256: Optional[str] = None
    package_sha256: Optional[str] = None
    diff_text: Optional[str] = None
    pkg_hash: Optional[str] = None
    src_hash: Optional[str] = None


@dataclass
class Finding:
    file_path: str = ""
    classification: str = "UNEXPLAINED"  # 'EXPECTED' | 'SUSPICIOUS' | 'UNEXPLAINED'
    signals: List[str] = field(default_factory=list)
    risk_level: str = "LOW"  # 'LOW' | 'MEDIUM' | 'HIGH'
    explanation: str = ""
    evidence: str = ""
    # Person B backward compatibility aliases:
    path: str = ""
    label: str = ""
    reason: str = ""
    weight: int = 0

    def __post_init__(self) -> None:
        # Sync file_path <-> path
        if self.path and not self.file_path:
            self.file_path = self.path
        elif self.file_path and not self.path:
            self.path = self.file_path

        # Sync classification <-> label
        if self.label and not self.classification:
            self.classification = self.label
        elif self.classification and not self.label:
            self.label = self.classification

        # Sync explanation <-> reason
        if self.reason and not self.explanation:
            self.explanation = self.reason
        elif self.explanation and not self.reason:
            self.reason = self.explanation


@dataclass
class Report:
    package_name: str = ""
    version: str = ""
    repo_url: Optional[str] = None
    commit_or_tag: Optional[str] = None
    overall_verdict: str = "CLEAN"  # 'CLEAN' | 'WARNING' | 'SUSPICIOUS'
    overall_risk_score: int = 0  # 0 to 100
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Person B backward compatibility aliases:
    package: str = ""
    source_found: bool = False
    risk: str = "LOW"

    def __post_init__(self) -> None:
        if self.package and not self.package_name:
            self.package_name = self.package
        elif self.package_name and not self.package:
            self.package = self.package_name

        if self.risk and not self.overall_verdict:
            self.overall_verdict = self.risk
        elif self.overall_verdict and not self.risk:
            self.risk = self.overall_verdict
