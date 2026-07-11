from dataclasses import dataclass, field


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
    debug: list[str] = field(default_factory=list)


@dataclass
class PackageScanResult:
    package: str
    result: ScanResult
