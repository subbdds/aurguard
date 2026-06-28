import os
from pathlib import Path


APP_NAME = "aurg"
DEFAULT_MODEL = "gemini-2.5-flash"
PROMPT_VERSION = "aurg-prompt-v1"
RULES_VERSION = "aurg-rules-v1"
GEMINI_ENDPOINT_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
USER_AGENT = "aurg/0.1"
MAX_PKGUILD_BYTES = 1024 * 1024
VERDICT_ORDER = {"Safe": 0, "Review": 1, "Dangerous": 2}


def load_dotenv(path: Path | None = None) -> None:
    env_path = path or find_dotenv()
    if not env_path or not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = strip_env_value(value.strip())
        if key and key.replace("_", "").isalnum():
            os.environ.setdefault(key, value)


def find_dotenv() -> Path | None:
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def strip_env_value(value: str) -> str:
    if "#" in value and not value.startswith(("'", '"')):
        value = value.split("#", 1)[0].rstrip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def configured_model() -> str:
    load_dotenv()
    return os.environ.get("AURG_MODEL", DEFAULT_MODEL)


def google_api_key() -> str | None:
    load_dotenv()
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
