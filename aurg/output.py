from .models import ScanResult


def print_result(result: ScanResult) -> None:
    print(f"Verdict: {result.verdict}")
    if result.verdict == "Safe":
        return

    for finding in result.findings:
        print()
        print(f"{finding.severity.upper()}: {finding.file}:{finding.line}")
        if finding.text:
            print(finding.text)
        print(finding.reason)


def confirm_continue() -> bool:
    try:
        answer = input("Continue anyway? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


def exit_code_for_verdict(verdict: str) -> int:
    return 0 if verdict == "Safe" else 1
