import difflib
import hashlib
import json

from .config import Config, PROMPT_VERSION, RULES_VERSION, VERDICT_ORDER
from .models import BuildFile, Finding, UpdatePackageInput, UpdatePackageResult, UpdateScanResult
from .state import PackageBaseline


MAX_UPDATE_DIFF_BYTES = 80_000
DIFF_CONTEXT_LINES = 5


def build_update_input(
    package: str,
    baseline: PackageBaseline,
    new_files: list[BuildFile],
    new_version: str | None = None,
) -> UpdatePackageInput:
    diff_files: list[BuildFile] = []
    old_by_name = {name: stored.text for name, stored in baseline.files.items()}
    new_by_name = {file.name: file.text for file in new_files}

    for name in sorted(set(old_by_name) | set(new_by_name), key=build_file_sort_key):
        old_text = old_by_name.get(name)
        new_text = new_by_name.get(name)
        if old_text == new_text:
            continue
        if old_text is None:
            body = f"status: added\n{numbered_text(new_text or '')}"
        elif new_text is None:
            body = f"status: deleted\n{numbered_text(old_text)}"
        else:
            body = "\n".join(
                difflib.unified_diff(
                    old_text.splitlines(),
                    new_text.splitlines(),
                    fromfile=f"old/{name}",
                    tofile=f"new/{name}",
                    lineterm="",
                    n=DIFF_CONTEXT_LINES,
                )
            )
        diff_files.append(BuildFile(name, body))

    return UpdatePackageInput(
        name=package,
        old_version=baseline.last_seen_version,
        new_version=new_version,
        baseline_reason=baseline.baseline_reason,
        files=diff_files,
        new_files=new_files,
    )


def scan_update_packages(
    packages: list[UpdatePackageInput],
    config: Config,
    no_ai: bool = False,
) -> UpdateScanResult:
    from .ai_client import scan_update_batch_with_ai

    if not packages:
        return UpdateScanResult("Safe", [], "No changed AUR build files found.", "update")

    package_results: list[UpdatePackageResult] = []
    scan_ready: list[UpdatePackageInput] = []
    for package in packages:
        reason = diff_scan_blocker(package)
        if reason:
            package_results.append(review_result(package, reason, "local-update"))
        else:
            scan_ready.append(package)

    if no_ai:
        package_results.extend(review_result(package, "AI update diff scan disabled.", "local-update") for package in scan_ready)
    else:
        for batch in split_evenly(scan_ready, min(config.update_ai_max_requests, len(scan_ready))):
            batch_results = scan_update_batch_with_ai(batch, config, compute_update_cache_key(batch, config.model))
            package_results.extend(batch_results.packages)

    ordered = sort_results_like_inputs(package_results, packages)
    verdict = worst_verdict([result.verdict for result in ordered])
    summary = update_summary(ordered)
    return UpdateScanResult(verdict=verdict, packages=ordered, summary=summary, source="update-ai")


def build_update_user_prompt(packages: list[UpdatePackageInput]) -> str:
    payload = {
        "scan_type": "aur_update_diff",
        "instructions": [
            "Review each package independently.",
            "Return one verdict per package.",
            "Use Safe only when the changed build-file lines do not introduce suspicious behavior.",
            "Use Review when context is insufficient or behavior is potentially risky.",
            "Use Dangerous for clearly unsafe or malicious update changes.",
        ],
        "packages": [
            {
                "name": package.name,
                "old_version": package.old_version,
                "new_version": package.new_version,
                "baseline_reason": package.baseline_reason,
                "files": [{"path": file.name, "diff": file.text} for file in package.files],
            }
            for package in packages
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def diff_scan_blocker(package: UpdatePackageInput) -> str | None:
    if not package.files:
        return "No changed build files were available for update diff scan."
    total = sum(len(file.text.encode("utf-8", errors="replace")) for file in package.files)
    if total > MAX_UPDATE_DIFF_BYTES:
        return "Changed build-file diff is too large for reliable update diff scan."
    for file in package.files:
        if not file.text.strip():
            return f"Changed build file {file.name} produced an empty diff."
    return None


def split_evenly(values: list[UpdatePackageInput], groups: int) -> list[list[UpdatePackageInput]]:
    if not values or groups <= 0:
        return []
    groups = min(groups, len(values))
    base, extra = divmod(len(values), groups)
    batches = []
    start = 0
    for index in range(groups):
        size = base + (1 if index < extra else 0)
        batches.append(values[start : start + size])
        start += size
    return batches


def compute_update_cache_key(packages: list[UpdatePackageInput], model: str) -> str:
    digest = hashlib.sha256()
    digest.update(model.encode())
    digest.update(PROMPT_VERSION.encode())
    digest.update(RULES_VERSION.encode())
    digest.update(b"update-diff-v1")
    for package in packages:
        digest.update(package.name.encode())
        digest.update(b"\0")
        for file in package.files:
            digest.update(file.name.encode())
            digest.update(b"\0")
            digest.update(file.text.encode("utf-8", errors="replace"))
            digest.update(b"\0")
    return digest.hexdigest()


def review_result(package: UpdatePackageInput, reason: str, source: str) -> UpdatePackageResult:
    file_name = package.files[0].name if package.files else "PKGBUILD"
    return UpdatePackageResult(
        name=package.name,
        verdict="Review",
        findings=[Finding(file=file_name, line=1, severity="Review", reason=reason, text="")],
        summary=reason,
        source=source,
    )


def sort_results_like_inputs(
    results: list[UpdatePackageResult],
    packages: list[UpdatePackageInput],
) -> list[UpdatePackageResult]:
    by_name = {result.name: result for result in results}
    return [by_name[package.name] for package in packages if package.name in by_name]


def worst_verdict(verdicts: list[str]) -> str:
    verdict = "Safe"
    for item in verdicts:
        if VERDICT_ORDER.get(item, 0) > VERDICT_ORDER[verdict]:
            verdict = item
    return verdict


def update_summary(results: list[UpdatePackageResult]) -> str:
    counts = {"Safe": 0, "Review": 0, "Dangerous": 0}
    for result in results:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1
    return f"Update scan results: {counts['Safe']} Safe, {counts['Review']} Review, {counts['Dangerous']} Dangerous."


def numbered_text(text: str) -> str:
    return "\n".join(f"{index}: {line}" for index, line in enumerate(text.splitlines(), start=1))


def build_file_sort_key(path: str) -> tuple[int, str]:
    priority = {"PKGBUILD": 0, ".SRCINFO": 1}
    return (priority.get(path, 2), path)
