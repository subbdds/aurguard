import json
from dataclasses import dataclass
import urllib.parse
import urllib.error
import urllib.request

from .config import AUR_REQUEST_TIMEOUT_SECONDS, MAX_AUR_FILE_BYTES, USER_AGENT
from .errors import AurgError
from .progress import Progress


AUR_RPC_BASE = "https://aur.archlinux.org/rpc/"
AUR_RPC_CHUNK_SIZE = 50


@dataclass
class AurPackageInfo:
    name: str
    package_base: str
    last_modified: int


def fetch_package_info(packages: list[str]) -> tuple[dict[str, AurPackageInfo], dict[str, str]]:
    info_by_package: dict[str, AurPackageInfo] = {}
    failures: dict[str, str] = {}
    unique_packages = unique_preserving_order(packages)
    if not unique_packages:
        return info_by_package, failures

    with Progress("Checking AUR package metadata", len(unique_packages)) as progress:
        for chunk in chunks(unique_packages, AUR_RPC_CHUNK_SIZE):
            chunk_info, chunk_failures = fetch_package_info_chunk(chunk)
            info_by_package.update(chunk_info)
            failures.update(chunk_failures)
            for _ in chunk:
                progress.advance()

    return info_by_package, failures


def fetch_package_info_chunk(packages: list[str]) -> tuple[dict[str, AurPackageInfo], dict[str, str]]:
    query = urllib.parse.urlencode([("v", "5"), ("type", "info"), *[("arg[]", package) for package in packages]])
    request = urllib.request.Request(f"{AUR_RPC_BASE}?{query}", headers={"User-Agent": USER_AGENT})

    try:
        with urllib.request.urlopen(request, timeout=AUR_REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", 200)
            body = response.read(MAX_AUR_FILE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise AurgError(f"AUR RPC returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise AurgError(f"AUR RPC network unavailable: {network_error_reason(exc)}") from exc
    except OSError as exc:
        raise AurgError(f"AUR RPC network unavailable: {exc}") from exc

    if status != 200:
        raise AurgError(f"AUR RPC returned HTTP {status}")
    if len(body) > MAX_AUR_FILE_BYTES:
        raise AurgError("AUR RPC response exceeded maximum size")

    try:
        data = json.loads(body.decode("utf-8"))
    except ValueError as exc:
        raise AurgError("AUR RPC returned malformed JSON") from exc

    if data.get("type") == "error":
        raise AurgError(f"AUR RPC returned error: {data.get('error', 'unknown error')}")

    info_by_name: dict[str, AurPackageInfo] = {}
    for item in data.get("results", []):
        if not isinstance(item, dict):
            continue
        parsed = parse_package_info(item)
        if parsed is not None:
            info_by_name[parsed.name] = parsed

    failures = {package: "AUR RPC package not found" for package in packages if package not in info_by_name}
    return info_by_name, failures


def network_error_reason(exc: urllib.error.URLError) -> str:
    reason = getattr(exc, "reason", exc)
    return str(reason)


def parse_package_info(item: dict) -> AurPackageInfo | None:
    name = item.get("Name")
    package_base = item.get("PackageBase") or name
    last_modified = item.get("LastModified")
    if not isinstance(name, str) or not isinstance(package_base, str):
        return None
    if not isinstance(last_modified, int) or isinstance(last_modified, bool):
        return None
    return AurPackageInfo(name=name, package_base=package_base, last_modified=last_modified)


def chunks(values: list[str], size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def unique_preserving_order(values: list[str]) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique
