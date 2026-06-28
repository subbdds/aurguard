import json
import urllib.parse
import urllib.request

from .config import Config, GEMINI_ENDPOINT_BASE, USER_AGENT, VERDICT_ORDER
from .models import BuildFile, Finding, ScanResult, UpdatePackageInput, UpdatePackageResult, UpdateScanResult
from .prompts import SYSTEM_PROMPT, build_user_prompt
from .schemas import AI_RESPONSE_SCHEMA, UPDATE_AI_RESPONSE_SCHEMA
from .update_scan import build_update_user_prompt, update_summary, worst_verdict


def scan_with_ai(files: list[BuildFile], config: Config, cache_key: str) -> ScanResult | None:
    api_key = config.api_key
    if not api_key:
        if config.require_ai:
            return api_failure_result(files, cache_key, "Google API key is required. Set GEMINI_API_KEY or GOOGLE_API_KEY in the environment or secrets file.")
        return None

    payload = build_gemini_payload(files)
    raw = send_gemini_payload(payload, config, files, cache_key)
    if isinstance(raw, ScanResult):
        return raw

    try:
        api_response = json.loads(raw.decode("utf-8"))
        output_text = extract_output_text(api_response)
        parsed = json.loads(output_text)
        return validate_ai_result(parsed, files, cache_key)
    except (TypeError, ValueError, KeyError):
        return api_failure_result(files, cache_key, "AI returned malformed output.")


def scan_update_batch_with_ai(
    packages: list[UpdatePackageInput],
    config: Config,
    cache_key: str,
) -> UpdateScanResult:
    if not packages:
        return UpdateScanResult("Safe", [], "No packages to scan.", "ai")

    api_key = config.api_key
    if not api_key:
        if config.require_ai:
            return update_api_failure_result(packages, "Google API key is required. Set GEMINI_API_KEY or GOOGLE_API_KEY in the environment or secrets file.")
        return update_api_failure_result(packages, "AI update scan unavailable.")

    payload = build_update_gemini_payload(packages)
    raw = send_gemini_payload(payload, config, [BuildFile(packages[0].name, "")], cache_key)
    if isinstance(raw, ScanResult):
        return update_api_failure_result(packages, raw.findings[0].reason if raw.findings else raw.summary)

    try:
        api_response = json.loads(raw.decode("utf-8"))
        output_text = extract_output_text(api_response)
        parsed = json.loads(output_text)
        return validate_update_ai_result(parsed, packages)
    except (TypeError, ValueError, KeyError):
        return update_api_failure_result(packages, "AI returned malformed update output.")


def send_gemini_payload(payload: dict, config: Config, files: list[BuildFile], cache_key: str) -> bytes | ScanResult:
    api_key = config.api_key
    if not api_key:
        return api_failure_result(files, cache_key, "Google API key is required. Set GEMINI_API_KEY or GOOGLE_API_KEY in the environment or secrets file.")

    data = json.dumps(payload).encode("utf-8")
    quoted_model = urllib.parse.quote(config.model, safe="")
    url = f"{GEMINI_ENDPOINT_BASE}/{quoted_model}:generateContent"
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return response.read(1024 * 1024)
    except OSError as exc:
        return api_failure_result(files, cache_key, f"AI request failed: {exc}")


def build_gemini_payload(files: list[BuildFile]) -> dict:
    return {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": build_user_prompt(files)}]}],
        "generationConfig": {
            "temperature": 0,
            "responseMimeType": "application/json",
            "responseSchema": AI_RESPONSE_SCHEMA,
        },
    }


def build_update_gemini_payload(packages: list[UpdatePackageInput]) -> dict:
    return {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": build_update_user_prompt(packages)}]}],
        "generationConfig": {
            "temperature": 0,
            "responseMimeType": "application/json",
            "responseSchema": UPDATE_AI_RESPONSE_SCHEMA,
        },
    }


def api_failure_result(files: list[BuildFile], cache_key: str, reason: str) -> ScanResult:
    first = files[0]
    return ScanResult(
        verdict="Review",
        findings=[
            Finding(
                file=first.name,
                line=1,
                severity="Review",
                reason=reason,
                text="AI scan unavailable.",
            )
        ],
        summary="AI scan was unavailable or invalid, so manual review is required.",
        source="ai-fallback",
        cache_key=cache_key,
    )


def extract_output_text(api_response: dict) -> str:
    if isinstance(api_response.get("output_text"), str):
        return api_response["output_text"]
    if isinstance(api_response.get("outputText"), str):
        return api_response["outputText"]

    texts: list[str] = []
    for step in api_response.get("steps", []):
        for part in step.get("content", []) if isinstance(step, dict) else []:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                texts.append(part["text"])
    if texts:
        return "".join(texts)

    candidate_texts: list[str] = []
    for candidate in api_response.get("candidates", []):
        content = candidate.get("content", {}) if isinstance(candidate, dict) else {}
        for part in content.get("parts", []) if isinstance(content, dict) else []:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                candidate_texts.append(part["text"])
    if candidate_texts:
        return "".join(candidate_texts)

    raise KeyError("output text not found")


def validate_ai_result(data: dict, files: list[BuildFile], cache_key: str) -> ScanResult:
    valid_files = {file.name for file in files}
    verdict = data.get("verdict")
    if verdict not in VERDICT_ORDER:
        raise ValueError("invalid verdict")

    findings: list[Finding] = []
    for item in data.get("findings", []):
        file_name = str(item.get("file", "PKGBUILD"))
        severity = item.get("severity", verdict)
        line = item.get("line", 1)
        reason = str(item.get("reason", "")).strip()

        if file_name not in valid_files:
            file_name = files[0].name
        if severity not in VERDICT_ORDER:
            severity = verdict
        if not isinstance(line, int) or line < 1:
            line = 1
        if not reason:
            reason = "Potentially risky PKGBUILD behavior."

        findings.append(
            Finding(
                file=file_name,
                line=line,
                severity=severity,
                reason=reason,
                text=line_text(files, file_name, line),
            )
        )

    return ScanResult(
        verdict=verdict,
        findings=findings,
        summary=str(data.get("summary", "")).strip() or verdict,
        source="ai",
        cache_key=cache_key,
    )


def validate_update_ai_result(data: dict, packages: list[UpdatePackageInput]) -> UpdateScanResult:
    valid_packages = {package.name: package for package in packages}
    raw_packages = data.get("packages", [])
    if not isinstance(raw_packages, list):
        raise ValueError("invalid update packages")

    results: list[UpdatePackageResult] = []
    seen: set[str] = set()
    for raw_package in raw_packages:
        if not isinstance(raw_package, dict):
            continue
        name = str(raw_package.get("name", ""))
        package = valid_packages.get(name)
        if package is None:
            continue
        verdict = raw_package.get("verdict")
        if verdict not in VERDICT_ORDER:
            raise ValueError("invalid update verdict")
        seen.add(name)

        valid_files = {file.name for file in package.new_files} | {file.name for file in package.files}
        findings: list[Finding] = []
        for item in raw_package.get("findings", []):
            if not isinstance(item, dict):
                continue
            file_name = str(item.get("file", "PKGBUILD"))
            severity = item.get("severity", verdict)
            line = item.get("line", 1)
            reason = str(item.get("reason", "")).strip()

            if file_name not in valid_files:
                file_name = package.files[0].name if package.files else "PKGBUILD"
            if severity not in VERDICT_ORDER:
                severity = verdict
            if not isinstance(line, int) or line < 1:
                line = 1
            if not reason:
                reason = "Potentially risky update behavior."

            findings.append(Finding(file=file_name, line=line, severity=severity, reason=reason, text=line_text(package.new_files, file_name, line)))

        results.append(
            UpdatePackageResult(
                name=name,
                verdict=verdict,
                findings=findings,
                summary=str(raw_package.get("summary", "")).strip() or verdict,
                source="ai",
            )
        )

    missing = [package for package in packages if package.name not in seen]
    if missing:
        raise ValueError("AI omitted update package verdicts")

    return UpdateScanResult(
        verdict=worst_verdict([result.verdict for result in results]),
        packages=results,
        summary=update_summary(results),
        source="ai",
    )


def update_api_failure_result(packages: list[UpdatePackageInput], reason: str) -> UpdateScanResult:
    results = []
    for package in packages:
        file_name = package.files[0].name if package.files else "PKGBUILD"
        results.append(
            UpdatePackageResult(
                name=package.name,
                verdict="Review",
                findings=[Finding(file=file_name, line=1, severity="Review", reason=reason, text="AI scan unavailable.")],
                summary="AI update scan was unavailable or invalid, so manual review is required.",
                source="ai-fallback",
            )
        )
    return UpdateScanResult("Review", results, update_summary(results), "ai-fallback")


def line_text(files: list[BuildFile], file_name: str, line: int) -> str:
    for file in files:
        if file.name == file_name:
            lines = file.text.splitlines()
            if 1 <= line <= len(lines):
                return lines[line - 1].strip()
    return ""
