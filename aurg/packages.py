from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

from .errors import AurgError
from .fetch import fetch_build_files
from .models import BuildFile


MAX_FETCH_WORKERS = 8


def list_foreign_packages() -> list[str] | None:
    try:
        completed = subprocess.run(["pacman", "-Qqm"], check=False, capture_output=True, text=True)
    except OSError:
        return None
    if completed.returncode not in {0, 1}:
        return None
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def fetch_packages(packages: list[str], scan_mode: str) -> tuple[dict[str, list[BuildFile]], dict[str, str]]:
    fetched: dict[str, list[BuildFile]] = {}
    failures: dict[str, str] = {}
    unique_packages = unique_preserving_order(packages)
    if not unique_packages:
        return fetched, failures

    workers = min(MAX_FETCH_WORKERS, len(unique_packages))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(fetch_build_files, package, scan_mode): package for package in unique_packages}
        for future in as_completed(futures):
            package = futures[future]
            try:
                fetched[package] = future.result()
            except AurgError as exc:
                failures[package] = str(exc)

    return dict(sorted(fetched.items())), dict(sorted(failures.items()))


def unique_preserving_order(values: list[str]) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique
