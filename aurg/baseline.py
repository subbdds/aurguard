import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import APP_NAME
from .models import BuildFile, PackageBuild


BASELINE_VERSION = 1
BASELINE_FILE = "packages.json"


@dataclass
class BaselineCompare:
    unchanged: list[str]
    changed: list[PackageBuild]
    skipped_unavailable: list[str]


def default_state_dir() -> Path:
    xdg_state_home = os.environ.get("XDG_STATE_HOME")
    if xdg_state_home:
        return Path(xdg_state_home).expanduser() / APP_NAME
    return Path.home() / ".local" / "state" / APP_NAME


def default_baseline_path() -> Path:
    return default_state_dir() / BASELINE_FILE


def load_baseline(path: Path | None = None) -> dict:
    baseline_path = path or default_baseline_path()
    if not baseline_path.is_file():
        return empty_manifest()
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_manifest()
    if not isinstance(data, dict) or not isinstance(data.get("packages"), dict):
        return empty_manifest()
    if not isinstance(data.get("unavailable", {}), dict):
        data["unavailable"] = {}
    return data


def write_baseline(
    packages: dict[str, list[BuildFile]],
    scan_mode: str,
    path: Path | None = None,
    unavailable: dict[str, dict] | None = None,
) -> None:
    baseline_path = path or default_baseline_path()
    manifest = build_manifest(packages, scan_mode, unavailable or {})
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = baseline_path.with_name(f"{baseline_path.name}.tmp")
    tmp_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(baseline_path)


def merge_baseline(
    packages: dict[str, list[BuildFile]],
    scan_mode: str,
    path: Path | None = None,
    unavailable: dict[str, dict] | None = None,
) -> None:
    manifest = load_baseline(path)
    stored = baseline_packages_to_files(manifest)
    stored.update(packages)
    stored_unavailable = baseline_unavailable(manifest)
    for package in packages:
        stored_unavailable.pop(package, None)
    if unavailable:
        stored_unavailable.update(unavailable)
    write_baseline(stored, scan_mode, path, stored_unavailable)


def compare_to_baseline(packages: dict[str, list[BuildFile]], baseline: dict | None = None) -> BaselineCompare:
    manifest = baseline if baseline is not None else load_baseline()
    stored_packages = manifest.get("packages", {})
    unavailable = baseline_unavailable(manifest)
    unchanged = []
    changed = []
    skipped_unavailable = []

    for package, files in sorted(packages.items()):
        if package in unavailable:
            skipped_unavailable.append(package)
            continue
        stored = stored_packages.get(package)
        if isinstance(stored, dict) and stored.get("files") == encode_files(files):
            unchanged.append(package)
        else:
            changed.append(PackageBuild(package, files))

    return BaselineCompare(unchanged=unchanged, changed=changed, skipped_unavailable=skipped_unavailable)


def build_manifest(packages: dict[str, list[BuildFile]], scan_mode: str, unavailable: dict[str, dict] | None = None) -> dict:
    return {
        "version": BASELINE_VERSION,
        "scan_mode": scan_mode,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "packages": {
            package: {
                "files": encode_files(files),
            }
            for package, files in sorted(packages.items())
        },
        "unavailable": unavailable or {},
    }


def empty_manifest() -> dict:
    return {
        "version": BASELINE_VERSION,
        "scan_mode": "",
        "updated_at": "",
        "packages": {},
        "unavailable": {},
    }


def encode_files(files: list[BuildFile]) -> list[dict[str, str]]:
    return [
        {
            "name": file.name,
            "sha256": file_hash(file),
            "text": file.text,
        }
        for file in sorted(files, key=lambda item: item.name)
    ]


def baseline_packages_to_files(manifest: dict) -> dict[str, list[BuildFile]]:
    packages: dict[str, list[BuildFile]] = {}
    stored = manifest.get("packages", {})
    if not isinstance(stored, dict):
        return packages

    for package, package_data in stored.items():
        if not isinstance(package, str) or not isinstance(package_data, dict):
            continue
        files = []
        for item in package_data.get("files", []):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            text = item.get("text")
            if isinstance(name, str) and isinstance(text, str):
                files.append(BuildFile(name, text))
        if files:
            packages[package] = files
    return packages


def baseline_unavailable(manifest: dict | None = None) -> dict[str, dict]:
    data = manifest if manifest is not None else load_baseline()
    unavailable = data.get("unavailable", {})
    if not isinstance(unavailable, dict):
        return {}
    clean: dict[str, dict] = {}
    for package, item in unavailable.items():
        if isinstance(package, str) and isinstance(item, dict):
            clean[package] = item
    return clean


def unavailable_packages(manifest: dict | None = None) -> set[str]:
    return set(baseline_unavailable(manifest))


def unavailable_from_failures(failures: dict[str, str]) -> dict[str, dict]:
    unavailable = {}
    for package, reason in failures.items():
        status = unavailable_status(reason)
        if status is None:
            continue
        unavailable[package] = {
            "status": status,
            "reason": reason,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    return unavailable


def unavailable_status(reason: str) -> int | None:
    if "HTTP 404" in reason:
        return 404
    if "HTTP 429" in reason:
        return 429
    return None


def file_hash(file: BuildFile) -> str:
    digest = hashlib.sha256()
    digest.update(file.name.encode())
    digest.update(b"\0")
    digest.update(file.text.encode("utf-8", errors="replace"))
    return digest.hexdigest()
