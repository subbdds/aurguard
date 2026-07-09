import io
import re
import tarfile
from html.parser import HTMLParser
from pathlib import PurePosixPath
import urllib.parse
import urllib.error
import urllib.request

from .config import AUR_REQUEST_TIMEOUT_SECONDS, MAX_AUR_FILE_BYTES, MAX_AUR_SCAN_FILES, MAX_AUR_SNAPSHOT_BYTES, MAX_AUR_TREE_PAGES, USER_AGENT
from .errors import AurgError
from .models import BuildFile


EXACT_SCAN_FILES = {"PKGBUILD", ".SRCINFO"}
SCAN_FILE_SUFFIXES = (".install", ".patch", ".diff", ".sh", ".service", ".timer", ".desktop")


class CgitTreeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.files: set[str] = set()
        self.dirs: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return

        attr_map = dict(attrs)
        href = attr_map.get("href")
        if not href:
            return

        path = path_from_tree_href(href)
        if path and is_safe_repo_path(path):
            classes = set((attr_map.get("class") or "").split())
            if "ls-dir" in classes:
                self.dirs.add(path)
            else:
                self.files.add(path)


def fetch_build_files(package: str, scan_mode: str = "full") -> list[BuildFile]:
    validate_package_name(package)
    try:
        return fetch_build_files_snapshot(package, scan_mode)
    except AurgError as exc:
        if not should_fallback_from_snapshot_error(str(exc)):
            raise

    if scan_mode == "pkgbuild":
        return [BuildFile("PKGBUILD", fetch_plain_file(package, "PKGBUILD"))]

    discovered = discover_build_file_paths(package)
    if "PKGBUILD" not in discovered:
        raise AurgError("AUR tree did not contain PKGBUILD")

    if len(discovered) > MAX_AUR_SCAN_FILES:
        raise AurgError(f"AUR package has too many scan-relevant files ({len(discovered)})")

    files = []
    for path in sort_build_file_paths(discovered):
        files.append(BuildFile(path, fetch_plain_file(package, path)))
    return files


def fetch_build_files_snapshot(package: str, scan_mode: str = "full") -> list[BuildFile]:
    body = fetch_url(build_cgit_snapshot_url(package), MAX_AUR_SNAPSHOT_BYTES)
    files = read_snapshot_build_files(body, scan_mode)
    if not files:
        raise AurgError("AUR snapshot did not contain scan-relevant build files")
    if not any(file.name == "PKGBUILD" for file in files):
        raise AurgError("AUR snapshot did not contain PKGBUILD")
    return files


def read_snapshot_build_files(body: bytes, scan_mode: str = "full") -> list[BuildFile]:
    paths: list[str] = []
    text_by_path: dict[str, str] = {}

    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                path = snapshot_member_path(member.name)
                if path is None:
                    continue
                if scan_mode == "pkgbuild" and path != "PKGBUILD":
                    continue
                if scan_mode != "pkgbuild" and not should_scan_build_file(path):
                    continue
                if member.size > MAX_AUR_FILE_BYTES:
                    raise AurgError(f"AUR snapshot file exceeded maximum scan size: {path}")
                if path not in text_by_path:
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    text_by_path[path] = extracted.read(MAX_AUR_FILE_BYTES + 1).decode("utf-8", errors="replace")
                    paths.append(path)
                if len(paths) > MAX_AUR_SCAN_FILES:
                    raise AurgError(f"AUR package has too many scan-relevant files ({len(paths)})")
    except tarfile.TarError as exc:
        raise AurgError("AUR snapshot was not a valid tar.gz archive") from exc

    return [BuildFile(path, text_by_path[path]) for path in sort_build_file_paths(paths)]


def snapshot_member_path(name: str) -> str | None:
    if "\0" in name or name.startswith("/"):
        return None
    parts = name.split("/")
    if len(parts) > 1:
        path = "/".join(parts[1:])
    else:
        path = name
    if not is_safe_repo_path(path):
        return None
    return path


def should_fallback_from_snapshot_error(reason: str) -> bool:
    return "snapshot did not contain" in reason or "not a valid tar.gz" in reason


def fetch_pkgbuild(package: str) -> str:
    validate_package_name(package)
    return fetch_plain_file(package, "PKGBUILD")


def validate_package_name(package: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9@._+:-]+", package):
        raise AurgError("package name contains unsupported characters")


def discover_build_file_paths(package: str) -> set[str]:
    pending = [""]
    visited: set[str] = set()
    matching_paths: set[str] = set()

    while pending:
        tree_path = pending.pop(0)
        if tree_path in visited:
            continue
        if len(visited) >= MAX_AUR_TREE_PAGES:
            raise AurgError("AUR tree is too large to scan safely")

        visited.add(tree_path)
        page = fetch_tree_page(package, tree_path)
        parser = CgitTreeParser()
        parser.feed(page)

        for path in parser.files:
            if should_scan_build_file(path):
                matching_paths.add(path)

        for path in sorted(parser.dirs):
            if path in visited or path in pending:
                continue
            pending.append(path)

    return matching_paths


def fetch_tree_page(package: str, path: str = "") -> str:
    url = build_cgit_url("tree", package, path)
    body = fetch_url(url, MAX_AUR_FILE_BYTES)
    text = body.decode("utf-8", errors="replace")
    if "<!DOCTYPE html" not in text[:500] and "<html" not in text[:500].lower():
        raise AurgError("AUR did not return a cgit tree page")
    return text


def fetch_plain_file(package: str, path: str) -> str:
    if not is_safe_repo_path(path):
        raise AurgError(f"AUR returned unsafe path: {path}")

    url = build_cgit_url("plain", package, path)
    body = fetch_url(url, MAX_AUR_FILE_BYTES)
    text = body.decode("utf-8", errors="replace")
    if "<!DOCTYPE html" in text[:200] or "<html" in text[:200].lower():
        raise AurgError(f"AUR did not return a raw file for {path}")
    return text


def fetch_url(url: str, byte_limit: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urllib.request.urlopen(request, timeout=AUR_REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", 200)
            body = response.read(byte_limit + 1)
    except urllib.error.HTTPError as exc:
        raise AurgError(f"AUR returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise AurgError(f"network unavailable or AUR unreachable: {network_error_reason(exc)}") from exc
    except OSError as exc:
        raise AurgError(f"network unavailable or AUR unreachable: {exc}") from exc

    if status != 200:
        raise AurgError(f"AUR returned HTTP {status}")
    if len(body) > byte_limit:
        raise AurgError("AUR response exceeded maximum scan size")

    return body


def network_error_reason(exc: urllib.error.URLError) -> str:
    reason = getattr(exc, "reason", exc)
    return str(reason)


def build_cgit_url(kind: str, package: str, path: str = "") -> str:
    quoted_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/") if part)
    suffix = f"/{quoted_path}" if quoted_path else ""
    query = urllib.parse.urlencode({"h": package})
    return f"https://aur.archlinux.org/cgit/aur.git/{kind}{suffix}?{query}"


def build_cgit_snapshot_url(package: str) -> str:
    quoted_package = urllib.parse.quote(package, safe="")
    query = urllib.parse.urlencode({"h": package})
    return f"https://aur.archlinux.org/cgit/aur.git/snapshot/{quoted_package}.tar.gz?{query}"


def path_from_tree_href(href: str) -> str | None:
    parsed = urllib.parse.urlparse(href)
    marker = "/cgit/aur.git/tree"
    if parsed.path == marker:
        return ""
    if not parsed.path.startswith(marker + "/"):
        return None
    return urllib.parse.unquote(parsed.path[len(marker) + 1 :])


def is_safe_repo_path(path: str) -> bool:
    if not path or "\0" in path or path.startswith("/"):
        return False
    parts = path.split("/")
    return bool(parts) and all(part not in {"", ".", ".."} for part in parts)


def should_scan_build_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in EXACT_SCAN_FILES or name.endswith(SCAN_FILE_SUFFIXES)


def sort_build_file_paths(paths: set[str] | list[str]) -> list[str]:
    priority = {"PKGBUILD": 0, ".SRCINFO": 1}
    return sorted(paths, key=lambda path: (priority.get(path, 2), path))
