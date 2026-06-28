import hashlib
from pathlib import Path

from .ai_client import scan_with_ai
from .config import Config, PROMPT_VERSION, RULES_VERSION
from .fetch import should_scan_build_file, sort_build_file_paths
from .local_rules import scan_with_local_rules
from .models import BuildFile, ScanResult


def scan_files(files: list[BuildFile], config: Config, no_ai: bool = False) -> ScanResult:
    cache_key = compute_cache_key(files, config.model)

    if not no_ai:
        ai_result = scan_with_ai(files, config, cache_key)
        if ai_result:
            return ai_result

    fallback = scan_with_local_rules(files)
    fallback.cache_key = cache_key
    return fallback


def scan_local_pkgbuild(path: Path, config: Config, no_ai: bool = False) -> ScanResult:
    if path.is_dir():
        files = read_local_build_files(path, config.scan_mode)
        return scan_files(files, config, no_ai)
    if not path.is_file():
        raise SystemExit(f"PKGBUILD not found: {path}")
    return scan_files([BuildFile("PKGBUILD", read_text(path))], config, no_ai)


def scan_fake_pkgbuild(path: Path, config: Config, no_ai: bool = False) -> ScanResult:
    if not path.is_file():
        raise SystemExit(f"Fake PKGBUILD not found: {path}")
    return scan_files([BuildFile(path.name, read_text(path))], config, no_ai)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit(f"Could not read {path}: {exc}") from exc


def read_local_build_files(path: Path, scan_mode: str = "full") -> list[BuildFile]:
    pkgbuild = path / "PKGBUILD"
    if not pkgbuild.is_file():
        raise SystemExit(f"PKGBUILD not found: {pkgbuild}")

    if scan_mode == "pkgbuild":
        return [BuildFile("PKGBUILD", read_text(pkgbuild))]

    paths = []
    for candidate in path.rglob("*"):
        if candidate.is_file():
            relative = candidate.relative_to(path).as_posix()
            if should_scan_build_file(relative):
                paths.append(relative)

    return [BuildFile(relative, read_text(path / relative)) for relative in sort_build_file_paths(paths)]


def compute_cache_key(files: list[BuildFile], model: str) -> str:
    digest = hashlib.sha256()
    digest.update(model.encode())
    digest.update(PROMPT_VERSION.encode())
    digest.update(RULES_VERSION.encode())
    for file in sorted(files, key=lambda item: item.name):
        digest.update(file.name.encode())
        digest.update(b"\0")
        digest.update(file.text.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()
