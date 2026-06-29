from dataclasses import dataclass


@dataclass
class BuildFile:
    name: str
    text: str


@dataclass
class PackageBuild:
    name: str
    files: list[BuildFile]


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
class PackageScanResult:
    package: str
    result: ScanResult
