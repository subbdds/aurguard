import shutil
import subprocess
import sys

from .config import Config
from .errors import AurgError
from .fetch import fetch_build_files
from .output import confirm_continue, print_result
from .scanner import scan_files


def install_package(package: str, config: Config, no_ai: bool = False, force_dangerous: bool = False) -> int:
    try:
        files = fetch_build_files(package, config.scan_mode)
    except AurgError as exc:
        print(f"Fetch failed: {exc}", file=sys.stderr)
        return 1

    result = scan_files(files, config, no_ai)
    print_result(result)

    if result.verdict == "Dangerous" and not force_dangerous:
        print("Installation blocked.")
        return 1

    if result.verdict == "Review" and not confirm_continue():
        print("Installation cancelled.")
        return 1

    helper = find_aur_helper(config.aur_helper)
    if not helper:
        if config.aur_helper == "auto":
            print("No AUR helper found. Install yay or paru, then retry.", file=sys.stderr)
        else:
            print(f"Configured AUR helper not found: {config.aur_helper}", file=sys.stderr)
        return 1

    print(f"Running: {helper} -S {package}")
    completed = subprocess.run([helper, "-S", package], check=False)
    return completed.returncode


def find_aur_helper(preference: str = "auto") -> str | None:
    if preference != "auto":
        return shutil.which(preference)

    for name in ("yay", "paru"):
        found = shutil.which(name)
        if found:
            return found
    return None
