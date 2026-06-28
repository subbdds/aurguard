import re
import urllib.parse
import urllib.request

from .config import MAX_PKGUILD_BYTES, USER_AGENT
from .errors import AurgError


def fetch_pkgbuild(package: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9@._+:-]+", package):
        raise AurgError("package name contains unsupported characters")

    query = urllib.parse.urlencode({"h": package})
    url = f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?{query}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = getattr(response, "status", 200)
            body = response.read(MAX_PKGUILD_BYTES)
    except OSError as exc:
        raise AurgError(str(exc)) from exc

    if status != 200:
        raise AurgError(f"AUR returned HTTP {status}")

    text = body.decode("utf-8", errors="replace")
    if "<!DOCTYPE html" in text[:200] or "<html" in text[:200].lower():
        raise AurgError("AUR did not return a raw PKGBUILD")
    return text
