from dataclasses import dataclass


@dataclass
class BuildFile:
    name: str
    text: str


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    reason: str
    text: str = ""


@dataclass
class ScanResult:
    verdict: str
    findings: list[Finding]
    summary: str
    source: str
    cache_key: str


@dataclass
class UpdatePackageInput:
    name: str
    old_version: str | None
    new_version: str | None
    baseline_reason: str
    files: list[BuildFile]
    new_files: list[BuildFile]


@dataclass
class UpdatePackageResult:
    name: str
    verdict: str
    findings: list[Finding]
    summary: str
    source: str


@dataclass
class UpdateScanResult:
    verdict: str
    packages: list[UpdatePackageResult]
    summary: str
    source: str
