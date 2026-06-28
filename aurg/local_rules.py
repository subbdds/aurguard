import re

from .config import VERDICT_ORDER
from .models import BuildFile, Finding, ScanResult


LOCAL_RULES = [
    ("Dangerous", re.compile(r"\b(?:curl|wget)\b[^\n|;&]*\|[^\n]*(?:sh|bash)\b"), "Downloads and executes a remote script."),
    ("Dangerous", re.compile(r"\bbase64\b[^\n|;&]*(?:-d|--decode)[^\n|;&]*\|[^\n]*(?:sh|bash)\b"), "Decodes base64 and executes it as shell."),
    ("Dangerous", re.compile(r"\b(?:sudo|su|pkexec)\b"), "Attempts privilege escalation inside build files."),
    ("Dangerous", re.compile(r"\bchmod\b[^\n]*(?:u\+s|g\+s|\+s|[0-7]*[2367][0-7]{2})\b"), "Sets setuid or setgid permissions."),
    ("Dangerous", re.compile(r"\brm\b[^\n]*-r[f]?\b[^\n]*(?:/\s|/\*|\$HOME|~)"), "Removes broad unsafe paths."),
    ("Dangerous", re.compile(r">\s*/(?:etc|usr|bin|sbin|lib|lib64|opt|var|home|root)\b"), "Writes outside package staging paths."),
    ("Review", re.compile(r"\bsha(?:256|512)sums=\([^)]*['\"]SKIP['\"]", re.DOTALL), "Source integrity is not pinned."),
    ("Review", re.compile(r"\beval\b"), "Uses eval, which can hide executed commands."),
    ("Review", re.compile(r"\b(?:curl|wget|nc|ncat|socat|python\s+-m\s+http\.server)\b"), "Performs network-related activity."),
    ("Review", re.compile(r"\bsystemctl\b[^\n]*\benable\b"), "Enables a systemd unit."),
    ("Review", re.compile(r"\b(?:crontab|/etc/cron|\.config/autostart|xdg-autostart)\b"), "Touches cron or autostart behavior."),
]


def scan_with_local_rules(files: list[BuildFile]) -> ScanResult:
    finding_by_line: dict[tuple[str, int], Finding] = {}
    for build_file in files:
        for line_no, line in enumerate(build_file.text.splitlines(), start=1):
            for severity, pattern, reason in LOCAL_RULES:
                if pattern.search(line):
                    key = (build_file.name, line_no)
                    current = finding_by_line.get(key)
                    next_finding = Finding(build_file.name, line_no, severity, reason, line.strip())
                    if current is None or VERDICT_ORDER[severity] > VERDICT_ORDER[current.severity]:
                        finding_by_line[key] = next_finding

    findings = list(finding_by_line.values())
    verdict = "Safe"
    for finding in findings:
        if VERDICT_ORDER[finding.severity] > VERDICT_ORDER[verdict]:
            verdict = finding.severity

    return ScanResult(
        verdict=verdict,
        findings=findings,
        summary="No suspicious behavior found." if verdict == "Safe" else "Static fallback scan found suspicious behavior.",
        source="local",
        cache_key="",
    )
