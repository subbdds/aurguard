import shutil
import subprocess
import sys

from .errors import AurgError
from .fetch import fetch_build_files
from .output import confirm_continue, print_result
from .scanner import scan_files


def install_package(package: str, model: str, no_ai: bool = False, force_dangerous: bool = False) -> int:
    try:
        files = fetch_build_files(package)
    except AurgError as exc:
        print(f"Fetch failed: {exc}", file=sys.stderr)
        return 1

    result = scan_files(files, model, no_ai)
    print_result(result)

    if result.verdict == "Dangerous" and not force_dangerous:
        print("Installation blocked.")
        return 1

    if result.verdict == "Review" and not confirm_continue():
        print("Installation cancelled.")
        return 1

    helper = find_aur_helper()
    if not helper:
        print("No AUR helper found. Install yay or paru, then retry.", file=sys.stderr)
        return 1

    print(f"Running: {helper} -S {package}")
    completed = subprocess.run([helper, "-S", package], check=False)
    return completed.returncode


def find_aur_helper() -> str | None:
    for name in ("yay", "paru"):
        found = shutil.which(name)
        if found:
            return found
    return None
