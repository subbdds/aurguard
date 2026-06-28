import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import ConfigError, default_state_path
from .models import BuildFile


STATE_VERSION = 1


@dataclass
class StoredBuildFile:
    sha256: str
    text: str


@dataclass
class PackageBaseline:
    name: str
    baseline_reason: str
    last_seen_version: str | None
    files: dict[str, StoredBuildFile]


@dataclass
class PackageState:
    packages: dict[str, PackageBaseline]


def load_state(path: Path | None = None) -> PackageState:
    state_path = path or default_state_path()
    if not state_path.is_file():
        return PackageState(packages={})

    try:
        data = json.loads(state_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Could not read aurg state file {state_path}: {exc}") from exc

    raw_packages = data.get("packages", {}) if isinstance(data, dict) else {}
    packages: dict[str, PackageBaseline] = {}
    if not isinstance(raw_packages, dict):
        return PackageState(packages={})

    for name, raw_package in raw_packages.items():
        if not isinstance(name, str) or not isinstance(raw_package, dict):
            continue
        raw_files = raw_package.get("files", {})
        if not isinstance(raw_files, dict):
            continue
        files: dict[str, StoredBuildFile] = {}
        for file_name, raw_file in raw_files.items():
            if not isinstance(file_name, str) or not isinstance(raw_file, dict):
                continue
            text = raw_file.get("text")
            sha256 = raw_file.get("sha256")
            if not isinstance(text, str):
                continue
            if not isinstance(sha256, str):
                sha256 = hash_text(text)
            files[file_name] = StoredBuildFile(sha256=sha256, text=text)
        if files:
            version = raw_package.get("last_seen_version")
            packages[name] = PackageBaseline(
                name=name,
                baseline_reason=str(raw_package.get("baseline_reason") or "unknown"),
                last_seen_version=version if isinstance(version, str) else None,
                files=files,
            )
    return PackageState(packages=packages)


def save_state(state: PackageState, path: Path | None = None) -> None:
    state_path = path or default_state_path()
    data: dict[str, Any] = {
        "version": STATE_VERSION,
        "packages": {
            name: {
                "baseline_reason": package.baseline_reason,
                "last_seen_version": package.last_seen_version,
                "files": {
                    file_name: {"sha256": stored.sha256, "text": stored.text}
                    for file_name, stored in sorted(package.files.items())
                },
            }
            for name, package in sorted(state.packages.items())
        },
    }

    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not write aurg state file {state_path}: {exc}") from exc


def update_baseline(
    state: PackageState,
    package: str,
    files: list[BuildFile],
    baseline_reason: str,
    version: str | None = None,
) -> None:
    state.packages[package] = PackageBaseline(
        name=package,
        baseline_reason=baseline_reason,
        last_seen_version=version,
        files={file.name: StoredBuildFile(sha256=hash_text(file.text), text=file.text) for file in files},
    )


def files_match(baseline: PackageBaseline, files: list[BuildFile]) -> bool:
    current = {file.name: hash_text(file.text) for file in files}
    previous = {name: stored.sha256 for name, stored in baseline.files.items()}
    return current == previous


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
