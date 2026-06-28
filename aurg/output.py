from .models import ScanResult, UpdateScanResult


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


def print_update_result(result: UpdateScanResult) -> None:
    print(result.summary)
    for package in result.packages:
        print(f"{package.name}: {package.verdict} ({package.source})")
        if package.summary:
            print(package.summary)
        for finding in package.findings:
            print(f"{finding.severity.upper()}: {package.name}/{finding.file}:{finding.line}")
            if finding.text:
                print(finding.text)
            print(finding.reason)
    print()
    print(f"Final update verdict: {result.verdict}")


def confirm_continue() -> bool:
    try:
        answer = input("Continue anyway? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes", "д", "н"}


def exit_code_for_verdict(verdict: str) -> int:
    return 0 if verdict == "Safe" else 1
