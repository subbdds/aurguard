import shutil
import subprocess
import sys
from dataclasses import dataclass

from .baseline import compare_to_baseline, merge_baseline, unavailable_from_failures, unavailable_packages
from .config import Config
from .errors import AurgError
from .fetch import fetch_build_files
from .models import BuildFile
from .output import confirm_continue, confirm_update_continue, print_package_result, print_result
from .packages import fetch_packages, list_foreign_packages, unique_preserving_order
from .scanner import scan_files, scan_package_groups


NO_INSTALL_SYNC_SHORT_FLAGS = set("silgcw")
NO_INSTALL_SYNC_LONG_OPTIONS = {
    "--search",
    "--info",
    "--list",
    "--groups",
    "--clean",
    "--downloadonly",
}
VALUE_OPTIONS = {
    "--assume-installed",
    "--cachedir",
    "--color",
    "--config",
    "--dbpath",
    "--gpgdir",
    "--hookdir",
    "--ignore",
    "--ignoregroup",
    "--logfile",
    "--root",
}


@dataclass
class HelperAction:
    scan: bool
    scan_updates: bool
    packages: list[str]


def install_package(package: str, config: Config, no_ai: bool = False, force_dangerous: bool = False) -> int:
    return run_scanned_helper_command(["-S", package], [package], False, config, no_ai, force_dangerous)


def run_helper_command(args: list[str], config: Config, no_ai: bool = False, force_dangerous: bool = False) -> int:
    action = classify_helper_args(args)
    if not action.scan:
        return run_helper(args, config)

    return run_scanned_helper_command(args, action.packages, action.scan_updates, config, no_ai, force_dangerous)


def run_scanned_helper_command(
    args: list[str],
    packages: list[str],
    scan_updates: bool,
    config: Config,
    no_ai: bool = False,
    force_dangerous: bool = False,
) -> int:
    helper = find_aur_helper(config.aur_helper)
    if not helper:
        print_missing_helper(config)
        return 1

    packages_to_scan = unique_preserving_order(packages)
    if scan_updates:
        fetched_updates = scan_full_system_update(config, no_ai, force_dangerous)
        if fetched_updates is None:
            return 1

    if packages_to_scan and not scan_packages(packages_to_scan, config, no_ai, force_dangerous):
        return 1

    return_code = run_helper(args, config, helper)
    if return_code == 0:
        baseline_updates: dict[str, list[BuildFile]] = {}
        if scan_updates and fetched_updates:
            baseline_updates.update(fetched_updates)
        if packages_to_scan:
            fetched_installs, failures = fetch_packages(packages_to_scan, config.scan_mode, "Updating install baseline")
            baseline_updates.update(fetched_installs)
            unavailable = unavailable_from_failures(failures)
            for package, reason in failures.items():
                print(f"Baseline not updated for {package}: {reason}", file=sys.stderr)
        if baseline_updates:
            merge_baseline(baseline_updates, config.scan_mode, unavailable=unavailable if packages_to_scan else None)
        elif packages_to_scan and unavailable:
            merge_baseline({}, config.scan_mode, unavailable=unavailable)
    return return_code


def scan_packages(packages: list[str], config: Config, no_ai: bool = False, force_dangerous: bool = False) -> bool:
    for package in packages:
        try:
            files = fetch_build_files(package, config.scan_mode)
        except AurgError as exc:
            print(f"Fetch failed for {package}: {exc}", file=sys.stderr)
            return False

        result = scan_files(files, config, no_ai)
        print_result(result)

        if result.verdict == "Dangerous" and not force_dangerous:
            print(f"Installation blocked: {package}")
            return False

        if result.verdict == "Review" and not confirm_continue():
            print("Installation cancelled.")
            return False

    return True


def scan_full_system_update(config: Config, no_ai: bool = False, force_dangerous: bool = False) -> dict[str, list[BuildFile]] | None:
    packages = list_foreign_packages()
    if packages is None:
        print("Could not list installed foreign packages for update scanning.", file=sys.stderr)
        return None
    if not packages:
        return {}

    unavailable = unavailable_packages()
    skipped_unavailable = sorted(unavailable.intersection(packages))
    packages_to_fetch = [package for package in packages if package not in unavailable]
    if skipped_unavailable:
        print(f"AUR update scan: skipping {len(skipped_unavailable)} previously unavailable package(s).")

    fetched, failures = fetch_packages(packages_to_fetch, config.scan_mode, "Checking AUR update baseline")
    for package, reason in failures.items():
        print(f"Fetch failed for {package}: {reason}", file=sys.stderr)

    unavailable_failures = unavailable_from_failures(failures)
    if unavailable_failures:
        merge_baseline({}, config.scan_mode, unavailable=unavailable_failures)
        failures = {package: reason for package, reason in failures.items() if package not in unavailable_failures}

    comparison = compare_to_baseline(fetched)
    if failures:
        print("Could not fetch all installed AUR packages for update scanning.", file=sys.stderr)
        return None
    if not comparison.changed:
        print("AUR update scan: all installed package build files match baseline.")
        return fetched

    print(
        f"AUR update scan: {len(comparison.changed)} package(s) changed or missing from baseline; "
        f"{len(comparison.unchanged)} unchanged."
    )
    results = scan_package_groups(comparison.changed, config, no_ai)
    flagged = [result for result in results if result.result.verdict != "Safe"]
    for result in flagged:
        print_package_result(result)

    dangerous = [result for result in results if result.result.verdict == "Dangerous"]
    if dangerous and not force_dangerous:
        names = ", ".join(result.package for result in dangerous)
        print(f"Installation blocked: Dangerous update package(s): {names}")
        return None

    reviews = [result for result in results if result.result.verdict == "Review"]
    if reviews and not confirm_update_continue(len(reviews)):
        print("Installation cancelled.")
        return None

    return fetched


def run_helper(args: list[str], config: Config, helper: str | None = None) -> int:
    helper = helper or find_aur_helper(config.aur_helper)
    if not helper:
        print_missing_helper(config)
        return 1

    print(f"Running: {' '.join([helper, *args])}")
    completed = subprocess.run([helper, *args], check=False)
    return completed.returncode


def classify_helper_args(args: list[str]) -> HelperAction:
    has_sync = any(is_sync_option(arg) for arg in args)
    if not has_sync:
        return HelperAction(scan=False, scan_updates=False, packages=[])

    if has_no_install_sync_option(args):
        return HelperAction(scan=False, scan_updates=False, packages=[])

    scan_updates = has_system_update(args)
    packages = collect_sync_targets(args)
    if not scan_updates and not packages:
        return HelperAction(scan=False, scan_updates=False, packages=[])

    return HelperAction(scan=True, scan_updates=scan_updates, packages=packages)


def is_sync_option(arg: str) -> bool:
    return arg == "--sync" or (arg.startswith("-") and not arg.startswith("--") and "S" in arg[1:])


def has_no_install_sync_option(args: list[str]) -> bool:
    return any(is_no_install_sync_option(arg) for arg in args)


def is_no_install_sync_option(arg: str) -> bool:
    if arg.startswith("--"):
        return arg in NO_INSTALL_SYNC_LONG_OPTIONS
    if not is_sync_option(arg):
        return False
    return bool(set(arg[1:]) & NO_INSTALL_SYNC_SHORT_FLAGS)


def has_system_update(args: list[str]) -> bool:
    for arg in args:
        if arg == "--sysupgrade":
            return True
        if arg.startswith("-") and not arg.startswith("--") and "S" in arg[1:] and "u" in arg[1:]:
            return True
    return False


def collect_sync_targets(args: list[str]) -> list[str]:
    targets = []
    sync_seen = False
    skip_next = False

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if is_sync_option(arg):
            sync_seen = True
            continue
        if arg in VALUE_OPTIONS:
            skip_next = True
            continue
        if arg.startswith("--") and "=" in arg and arg.split("=", 1)[0] in VALUE_OPTIONS:
            continue
        if arg.startswith("-"):
            continue
        if sync_seen:
            targets.append(arg)

    return targets


def print_missing_helper(config: Config) -> None:
    if config.aur_helper == "auto":
        print("No AUR helper found. Install yay or paru, then retry.", file=sys.stderr)
    else:
        print(f"Configured AUR helper not found: {config.aur_helper}", file=sys.stderr)


def find_aur_helper(preference: str = "auto") -> str | None:
    if preference != "auto":
        return shutil.which(preference)

    for name in ("yay", "paru"):
        found = shutil.which(name)
        if found:
            return found
    return None
