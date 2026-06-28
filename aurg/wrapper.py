import shutil
import subprocess
import sys

from .errors import AurgError
from .fetch import fetch_pkgbuild
from .models import BuildFile
from .output import confirm_continue, print_result
from .scanner import scan_files


def install_package(package: str, model: str, no_ai: bool = False, force_dangerous: bool = False) -> int:
    try:
        pkgbuild = fetch_pkgbuild(package)
    except AurgError as exc:
        print(f"Fetch failed: {exc}", file=sys.stderr)
        return 1

    result = scan_files([BuildFile("PKGBUILD", pkgbuild)], model, no_ai)
    print_result(result)

    if result.verdict == "Dangerous" and not force_dangerous:
        print("Installation blocked.")
        return 1

    if result.verdict == "Review" and not confirm_continue():
        print("Installation cancelled.")
        return 1

    if result.verdict == "Safe":
        print("Package marked safe; continuing installation.")

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
