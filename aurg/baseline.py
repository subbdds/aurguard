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
    return data


def write_baseline(packages: dict[str, list[BuildFile]], scan_mode: str, path: Path | None = None) -> None:
    baseline_path = path or default_baseline_path()
    manifest = build_manifest(packages, scan_mode)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = baseline_path.with_name(f"{baseline_path.name}.tmp")
    tmp_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(baseline_path)


def merge_baseline(packages: dict[str, list[BuildFile]], scan_mode: str, path: Path | None = None) -> None:
    manifest = load_baseline(path)
    stored = baseline_packages_to_files(manifest)
    stored.update(packages)
    write_baseline(stored, scan_mode, path)


def compare_to_baseline(packages: dict[str, list[BuildFile]], baseline: dict | None = None) -> BaselineCompare:
    manifest = baseline if baseline is not None else load_baseline()
    stored_packages = manifest.get("packages", {})
    unchanged = []
    changed = []

    for package, files in sorted(packages.items()):
        stored = stored_packages.get(package)
        if isinstance(stored, dict) and stored.get("files") == encode_files(files):
            unchanged.append(package)
        else:
            changed.append(PackageBuild(package, files))

    return BaselineCompare(unchanged=unchanged, changed=changed)


def build_manifest(packages: dict[str, list[BuildFile]], scan_mode: str) -> dict:
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
    }


def empty_manifest() -> dict:
    return {
        "version": BASELINE_VERSION,
        "scan_mode": "",
        "updated_at": "",
        "packages": {},
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


def file_hash(file: BuildFile) -> str:
    digest = hashlib.sha256()
    digest.update(file.name.encode())
    digest.update(b"\0")
    digest.update(file.text.encode("utf-8", errors="replace"))
    return digest.hexdigest()
