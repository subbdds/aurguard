import shutil
import subprocess
import sys
from dataclasses import dataclass

from .config import Config, ConfigError
from .errors import AurgError
from .fetch import fetch_build_files
from .models import BuildFile, UpdatePackageInput
from .output import confirm_continue, print_result, print_update_result
from .scanner import scan_files
from .state import files_match, load_state, save_state, update_baseline
from .update_scan import build_update_input, scan_update_packages


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


@dataclass
class AurUpdate:
    name: str
    old_version: str | None = None
    new_version: str | None = None


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

    scanned_files: dict[str, list[BuildFile]] = {}
    scanned_versions: dict[str, str | None] = {}
    update_names: set[str] = set()
    if scan_updates:
        if not refresh_package_databases(helper):
            print("Could not refresh package databases before AUR update scan.", file=sys.stderr)
            return 1
        updates = list_aur_updates_info(helper)
        if updates is None:
            print("Could not list AUR updates for scanning.", file=sys.stderr)
            return 1
        update_names = {update.name for update in updates}
        update_files = scan_update_candidates(updates, config, no_ai, force_dangerous)
        if update_files is None:
            return 1
        scanned_files.update(update_files)
        scanned_versions.update({update.name: update.new_version for update in updates})

    packages_to_scan = [package for package in unique_preserving_order(packages) if package not in update_names]
    if packages_to_scan:
        package_files = scan_packages(packages_to_scan, config, no_ai, force_dangerous)
        if package_files is None:
            return 1
        scanned_files.update(package_files)

    code = run_helper(args, config, helper)
    if code == 0 and scanned_files:
        persist_scanned_baselines(scanned_files, "scanned-update" if scan_updates else "scanned-install", scanned_versions)
    return code


def scan_packages(
    packages: list[str],
    config: Config,
    no_ai: bool = False,
    force_dangerous: bool = False,
) -> dict[str, list[BuildFile]] | None:
    scanned: dict[str, list[BuildFile]] = {}
    for package in packages:
        try:
            files = fetch_build_files(package, config.scan_mode)
        except AurgError as exc:
            print(f"Fetch failed for {package}: {exc}", file=sys.stderr)
            return None

        result = scan_files(files, config, no_ai)
        print_result(result)

        if result.verdict == "Dangerous" and not force_dangerous:
            print(f"Installation blocked: {package}")
            return None

        if result.verdict == "Review" and not confirm_continue():
            print("Installation cancelled.")
            return None

        scanned[package] = files

    return scanned


def scan_update_candidates(
    updates: list[AurUpdate],
    config: Config,
    no_ai: bool = False,
    force_dangerous: bool = False,
) -> dict[str, list[BuildFile]] | None:
    if not updates:
        return {}

    try:
        state = load_state()
    except ConfigError as exc:
        print(f"State error: {exc}", file=sys.stderr)
        return None

    full_scan: list[str] = []
    changed: list[UpdatePackageInput] = []
    fetched: dict[str, list[BuildFile]] = {}
    skipped = 0

    for update in updates:
        try:
            files = fetch_build_files(update.name, config.scan_mode)
        except AurgError as exc:
            print(f"Fetch failed for {update.name}: {exc}", file=sys.stderr)
            return None
        fetched[update.name] = files

        baseline = state.packages.get(update.name)
        if baseline is None:
            full_scan.append(update.name)
            continue
        if files_match(baseline, files):
            skipped += 1
            continue
        changed.append(build_update_input(update.name, baseline, files, update.new_version))

    print(f"AUR updates: {len(updates)}")
    print(f"Unchanged build files: {skipped} skipped")
    print(f"Changed build files: {len(changed)} package(s)")
    if skipped == len(updates) and not full_scan and not changed:
        print("All AUR update build files match recorded baselines. No AI scan required.")

    scanned: dict[str, list[BuildFile]] = {}
    if full_scan:
        print(f"Unknown update baselines: {len(full_scan)} package(s), using full scan.")
        full_scanned = scan_packages(full_scan, config, no_ai, force_dangerous)
        if full_scanned is None:
            return None
        scanned.update(full_scanned)

    if changed:
        result = scan_update_packages(changed, config, no_ai)
        print_update_result(result)
        if result.verdict == "Dangerous" and not force_dangerous:
            dangerous = [package.name for package in result.packages if package.verdict == "Dangerous"]
            print(f"Installation blocked: {', '.join(dangerous)}")
            return None
        if result.verdict == "Review" and not confirm_continue():
            print("Installation cancelled.")
            return None
        for package in changed:
            scanned[package.name] = package.new_files

    for update in updates:
        if update.name not in scanned and update.name in fetched:
            scanned[update.name] = fetched[update.name]

    return scanned


def persist_scanned_baselines(
    scanned_files: dict[str, list[BuildFile]],
    baseline_reason: str,
    versions: dict[str, str | None] | None = None,
) -> None:
    try:
        state = load_state()
        for package, files in scanned_files.items():
            update_baseline(state, package, files, baseline_reason, (versions or {}).get(package))
        save_state(state)
    except ConfigError as exc:
        print(f"Could not update aurg package baselines: {exc}", file=sys.stderr)


def run_helper(args: list[str], config: Config, helper: str | None = None) -> int:
    helper = helper or find_aur_helper(config.aur_helper)
    if not helper:
        print_missing_helper(config)
        return 1

    print(f"Running: {' '.join([helper, *args])}")
    completed = subprocess.run([helper, *args], check=False)
    return completed.returncode


def refresh_package_databases(helper: str) -> bool:
    print(f"Refreshing package databases before AUR update scan: {helper} -Sy")
    completed = subprocess.run([helper, "-Sy"], check=False)
    return completed.returncode == 0


def list_aur_updates(helper: str) -> list[str] | None:
    updates = list_aur_updates_info(helper)
    if updates is None:
        return None
    return [update.name for update in updates]


def list_aur_updates_info(helper: str) -> list[AurUpdate] | None:
    completed = subprocess.run([helper, "-Qua"], check=False, capture_output=True, text=True)
    if completed.returncode not in {0, 1}:
        return None

    updates = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        name = parts[0]
        old_version = parts[1] if len(parts) >= 2 else None
        new_version = parts[3] if len(parts) >= 4 and parts[2] == "->" else None
        updates.append(AurUpdate(name=name, old_version=old_version, new_version=new_version))
    return updates


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


def unique_preserving_order(values: list[str]) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


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
