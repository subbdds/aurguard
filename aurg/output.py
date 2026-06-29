from .models import PackageScanResult, ScanResult


def print_result(result: ScanResult) -> None:
    if result.verdict == "Safe":
        print(f"SAFE: scan passed ({result.source})")
    else:
        print(f"{result.verdict} ({result.source})")

    if result.summary:
        print(result.summary)

    for finding in result.findings:
        print()
        print(f"{finding.severity.upper()}: {finding.file}:{finding.line}")
        if finding.text:
            print(finding.text)
        print(finding.reason)

    print()
    print(f"Final verdict: {result.verdict}")


def print_package_result(result: PackageScanResult) -> None:
    print(f"Package: {result.package}")
    print_result(result.result)


def confirm_continue() -> bool:
    try:
        answer = input("Continue anyway? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes", "д", "н"}


def confirm_update_continue(review_count: int) -> bool:
    try:
        answer = input(f"Continue with {review_count} package(s) requiring review? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes", "д", "н"}


def exit_code_for_verdict(verdict: str) -> int:
    return 0 if verdict == "Safe" else 1
