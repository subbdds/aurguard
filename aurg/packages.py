from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import time

from .errors import AurgError
from .fetch import fetch_build_files
from .models import BuildFile
from .progress import Progress


MAX_FETCH_WORKERS = 2
MAX_FETCH_ATTEMPTS = 3


def list_foreign_packages() -> list[str] | None:
    try:
        completed = subprocess.run(["pacman", "-Qqm"], check=False, capture_output=True, text=True)
    except OSError:
        return None
    if completed.returncode not in {0, 1}:
        return None
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def fetch_packages(packages: list[str], scan_mode: str, label: str = "Fetching AUR build files") -> tuple[dict[str, list[BuildFile]], dict[str, str]]:
    fetched: dict[str, list[BuildFile]] = {}
    failures: dict[str, str] = {}
    unique_packages = unique_preserving_order(packages)
    if not unique_packages:
        return fetched, failures

    workers = min(MAX_FETCH_WORKERS, len(unique_packages))
    with Progress(label, len(unique_packages)) as progress:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(fetch_build_files_with_retry, package, scan_mode): package for package in unique_packages}
            for future in as_completed(futures):
                package = futures[future]
                try:
                    fetched[package] = future.result()
                except AurgError as exc:
                    failures[package] = str(exc)
                finally:
                    progress.advance()

    return dict(sorted(fetched.items())), dict(sorted(failures.items()))


def fetch_build_files_with_retry(package: str, scan_mode: str) -> list[BuildFile]:
    last_error: AurgError | None = None
    for attempt in range(MAX_FETCH_ATTEMPTS):
        try:
            return fetch_build_files(package, scan_mode)
        except AurgError as exc:
            last_error = exc
            if not should_retry_fetch(str(exc)) or attempt == MAX_FETCH_ATTEMPTS - 1:
                break
            time.sleep(fetch_retry_delay(str(exc), attempt))
    if last_error is None:
        raise AurgError("fetch failed")
    raise last_error


def should_retry_fetch(reason: str) -> bool:
    return "HTTP 429" in reason or "Connection reset by peer" in reason or "timed out" in reason


def fetch_retry_delay(reason: str, attempt: int) -> float:
    if "HTTP 429" in reason:
        return 4.0 + attempt * 4.0
    return 1.0 + attempt * 2.0


def unique_preserving_order(values: list[str]) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique
