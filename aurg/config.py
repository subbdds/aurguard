import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


APP_NAME = "aurg"
DEFAULT_MODEL = "gemini-3.1-flash-lite"
DEFAULT_PROVIDER = "google"
DEFAULT_AUR_HELPER = "auto"
DEFAULT_SCAN_MODE = "full"
DEFAULT_MAX_UPDATE_REQUESTS = 4
PROMPT_VERSION = "aurg-prompt-v2"
RULES_VERSION = "aurg-rules-v1"
GEMINI_ENDPOINT_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
USER_AGENT = "aurg/0.1"
MAX_AUR_FILE_BYTES = 1024 * 1024
MAX_AUR_SCAN_FILES = 64
MAX_AUR_TREE_PAGES = 64
MAX_PKGUILD_BYTES = MAX_AUR_FILE_BYTES
VERDICT_ORDER = {"Safe": 0, "Review": 1, "Dangerous": 2}
VALID_AUR_HELPERS = {"auto", "yay", "paru"}
VALID_SCAN_MODES = {"full", "pkgbuild"}
VALID_PROVIDERS = {"google", "openai", "anthropic"}
IMPLEMENTED_PROVIDERS = {"google"}


class ConfigError(ValueError):
    pass


@dataclass
class ConfigPaths:
    config: Path
    secrets: Path


@dataclass
class Config:
    aur_helper: str = DEFAULT_AUR_HELPER
    scan_mode: str = DEFAULT_SCAN_MODE
    provider: str = DEFAULT_PROVIDER
    model: str = DEFAULT_MODEL
    require_ai: bool = True
    max_update_requests: int = DEFAULT_MAX_UPDATE_REQUESTS
    api_key: str | None = None
    config_path: Path | None = None
    secrets_path: Path | None = None


@dataclass
class ConfigOverrides:
    aur_helper: str | None = None
    scan_mode: str | None = None
    model: str | None = None


def default_config_dir() -> Path:
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home) / APP_NAME
    return Path.home() / ".config" / APP_NAME


def resolve_config_path(path: str | Path | None = None) -> Path:
    if path:
        return Path(path).expanduser()
    env_path = os.environ.get("AURG_CONFIG_FILE")
    if env_path:
        return Path(env_path).expanduser()
    return default_config_dir() / "config.toml"


def resolve_secrets_path(path: str | Path | None = None) -> Path:
    if path:
        return Path(path).expanduser()
    env_path = os.environ.get("AURG_SECRETS_FILE")
    if env_path:
        return Path(env_path).expanduser()
    return default_config_dir() / "secrets.env"


def resolve_config_paths(config_path: str | Path | None = None, secrets_path: str | Path | None = None) -> ConfigPaths:
    return ConfigPaths(
        config=resolve_config_path(config_path),
        secrets=resolve_secrets_path(secrets_path),
    )


def uses_default_config_paths(config_path: str | Path | None = None, secrets_path: str | Path | None = None) -> bool:
    return not config_path and not secrets_path and not os.environ.get("AURG_CONFIG_FILE") and not os.environ.get("AURG_SECRETS_FILE")


def load_config(
    config_path: str | Path | None = None,
    secrets_path: str | Path | None = None,
    overrides: ConfigOverrides | None = None,
) -> Config:
    paths = resolve_config_paths(config_path, secrets_path)
    data = read_toml_file(paths.config)

    config = Config(
        aur_helper=read_string(data, "aur_helper", DEFAULT_AUR_HELPER),
        scan_mode=read_string(data, "scan_mode", DEFAULT_SCAN_MODE),
        provider=read_string(data, "provider", DEFAULT_PROVIDER),
        model=read_string(data, "model", DEFAULT_MODEL),
        require_ai=read_bool(data, "require_ai", True),
        max_update_requests=read_int(data, "max_update_requests", DEFAULT_MAX_UPDATE_REQUESTS),
        config_path=paths.config,
        secrets_path=paths.secrets,
    )

    apply_env_overrides(config)
    if overrides:
        apply_cli_overrides(config, overrides)

    validate_config(config)
    config.api_key = resolve_api_key(config.provider, paths.secrets)
    return config


def read_toml_file(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid config file {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not read config file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Invalid config file {path}: expected a TOML table")
    return data


def read_string(data: dict, key: str, default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"Invalid config value {key}: expected a string")
    return value.strip()


def read_bool(data: dict, key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"Invalid config value {key}: expected true or false")
    return value


def read_int(data: dict, key: str, default: int) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"Invalid config value {key}: expected an integer")
    return value


def apply_env_overrides(config: Config) -> None:
    config.aur_helper = os.environ.get("AURG_AUR_HELPER", config.aur_helper)
    config.scan_mode = os.environ.get("AURG_SCAN_MODE", config.scan_mode)
    config.provider = os.environ.get("AURG_PROVIDER", config.provider)
    config.model = os.environ.get("AURG_MODEL", config.model)
    require_ai = os.environ.get("AURG_REQUIRE_AI")
    if require_ai is not None:
        config.require_ai = parse_env_bool("AURG_REQUIRE_AI", require_ai)
    max_update_requests = os.environ.get("AURG_MAX_UPDATE_REQUESTS")
    if max_update_requests is not None:
        config.max_update_requests = parse_env_int("AURG_MAX_UPDATE_REQUESTS", max_update_requests)


def apply_cli_overrides(config: Config, overrides: ConfigOverrides) -> None:
    if overrides.aur_helper is not None:
        config.aur_helper = overrides.aur_helper
    if overrides.scan_mode is not None:
        config.scan_mode = overrides.scan_mode
    if overrides.model is not None:
        config.model = overrides.model


def parse_env_bool(name: str, value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ConfigError(f"Invalid environment value {name}: expected true or false")


def parse_env_int(name: str, value: str) -> int:
    try:
        return int(value.strip())
    except ValueError as exc:
        raise ConfigError(f"Invalid environment value {name}: expected an integer") from exc


def validate_config(config: Config) -> None:
    if config.aur_helper not in VALID_AUR_HELPERS:
        raise ConfigError(f"Invalid aur_helper: {config.aur_helper}. Expected one of: {', '.join(sorted(VALID_AUR_HELPERS))}")
    if config.scan_mode not in VALID_SCAN_MODES:
        raise ConfigError(f"Invalid scan_mode: {config.scan_mode}. Expected one of: {', '.join(sorted(VALID_SCAN_MODES))}")
    if config.provider not in VALID_PROVIDERS:
        raise ConfigError(f"Invalid provider: {config.provider}. Expected one of: {', '.join(sorted(VALID_PROVIDERS))}")
    if config.provider not in IMPLEMENTED_PROVIDERS:
        raise ConfigError(f"Provider not implemented yet: {config.provider}. Only google is supported in this version.")
    if not config.model:
        raise ConfigError("Invalid model: expected a non-empty model name")
    if config.max_update_requests < 1:
        raise ConfigError("Invalid max_update_requests: expected an integer greater than or equal to 1")


def resolve_api_key(provider: str, secrets_path: Path) -> str | None:
    env_key = provider_api_env_names(provider)
    for name in env_key:
        value = os.environ.get(name)
        if value:
            return value

    secrets = parse_env_file(secrets_path)
    for name in env_key:
        value = secrets.get(name)
        if value:
            return value
    return None


def provider_api_env_names(provider: str) -> tuple[str, ...]:
    if provider == "google":
        return ("GEMINI_API_KEY", "GOOGLE_API_KEY")
    if provider == "openai":
        return ("OPENAI_API_KEY",)
    if provider == "anthropic":
        return ("ANTHROPIC_API_KEY",)
    return ()


def parse_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}

    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise ConfigError(f"Could not read secrets file {path}: {exc}") from exc

    for raw_line in lines:
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
            values[key] = value
    return values


def format_config(config: Config) -> str:
    require_ai = "true" if config.require_ai else "false"
    return "\n".join(
        [
            f'aur_helper = "{config.aur_helper}"',
            f'scan_mode = "{config.scan_mode}"',
            f'provider = "{config.provider}"',
            f'model = "{config.model}"',
            f"require_ai = {require_ai}",
            f"max_update_requests = {config.max_update_requests}",
            "",
        ]
    )


def write_config_file(path: Path, config: Config) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(format_config(config), encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not write config file {path}: {exc}") from exc


def write_secrets_file(path: Path, provider: str, api_key: str) -> None:
    names = provider_api_env_names(provider)
    if not names:
        raise ConfigError(f"No API key name is known for provider: {provider}")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as secrets_file:
            secrets_file.write(f"{names[0]}={quote_env_value(api_key)}\n")
        os.chmod(path, 0o600)
    except OSError as exc:
        raise ConfigError(f"Could not write secrets file {path}: {exc}") from exc


def quote_env_value(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


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
    return os.environ.get("AURG_MODEL", DEFAULT_MODEL)


def google_api_key() -> str | None:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
