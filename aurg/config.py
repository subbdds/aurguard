import os


APP_NAME = "aurg"
DEFAULT_MODEL = "gemini-2.5-flash"
PROMPT_VERSION = "aurg-prompt-v1"
RULES_VERSION = "aurg-rules-v1"
GEMINI_ENDPOINT_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
USER_AGENT = "aurg/0.1"
MAX_PKGUILD_BYTES = 1024 * 1024
VERDICT_ORDER = {"Safe": 0, "Review": 1, "Dangerous": 2}


def configured_model() -> str:
    return os.environ.get("AURG_MODEL", DEFAULT_MODEL)


def google_api_key() -> str | None:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
