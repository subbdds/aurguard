import json
import urllib.parse
import urllib.request

from .config import GEMINI_ENDPOINT_BASE, USER_AGENT, VERDICT_ORDER, google_api_key
from .models import BuildFile, Finding, ScanResult
from .prompts import SYSTEM_PROMPT, build_user_prompt
from .schemas import AI_RESPONSE_SCHEMA


def scan_with_ai(files: list[BuildFile], model: str, cache_key: str) -> ScanResult | None:
    api_key = google_api_key()
    if not api_key:
        return None

    payload = build_gemini_payload(files)
    data = json.dumps(payload).encode("utf-8")
    quoted_model = urllib.parse.quote(model, safe="")
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
            raw = response.read(1024 * 1024)
    except OSError as exc:
        return api_failure_result(files, cache_key, f"AI request failed: {exc}")

    try:
        api_response = json.loads(raw.decode("utf-8"))
        output_text = extract_output_text(api_response)
        parsed = json.loads(output_text)
        return validate_ai_result(parsed, files, cache_key)
    except (TypeError, ValueError, KeyError):
        return api_failure_result(files, cache_key, "AI returned malformed output.")


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


def line_text(files: list[BuildFile], file_name: str, line: int) -> str:
    for file in files:
        if file.name == file_name:
            lines = file.text.splitlines()
            if 1 <= line <= len(lines):
                return lines[line - 1].strip()
    return ""
