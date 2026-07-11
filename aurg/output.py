from .models import PackageScanResult, ScanResult


def print_result(result: ScanResult, full_output: bool = False) -> None:
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

    if full_output:
        print()
        print("Full output:")
        print(f"  verdict: {result.verdict}")
        print(f"  source: {result.source}")
        print(f"  summary: {result.summary or '(none)'}")
        print(f"  cache_key: {result.cache_key or '(none)'}")
        print(f"  findings: {len(result.findings)}")
        if result.findings:
            for index, finding in enumerate(result.findings, start=1):
                print(f"  finding {index}: {finding.severity} {finding.file}:{finding.line} - {finding.reason}")
        else:
            print("  findings_detail: none")
        if result.debug:
            print("  debug:")
            for item in result.debug:
                print(f"    - {item}")
        else:
            print("  debug: none")

    print()
    print(f"Final verdict: {result.verdict}")


def print_package_result(result: PackageScanResult, full_output: bool = False) -> None:
    print(f"Package: {result.package}")
    print_result(result.result, full_output)


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
