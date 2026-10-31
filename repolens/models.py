"""Shared data shapes. Everyone codes against these."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

DiffStatus = Literal["identical", "modified", "only_in_package", "only_in_source"]
Label = Literal["EXPECTED", "SUSPICIOUS", "UNEXPLAINED"]
Risk = Literal["LOW", "MEDIUM", "HIGH"]


@dataclass
class FileDiff:
    path: str
    status: DiffStatus
    pkg_hash: str | None = None
    src_hash: str | None = None


@dataclass
class Finding:
    path: str
    label: Label
    reason: str
    signals: list[str] = field(default_factory=list)
    weight: int = 0


@dataclass
class Report:
    package: str
    version: str
    source_found: bool
    findings: list[Finding] = field(default_factory=list)
    risk: Risk = "LOW"
