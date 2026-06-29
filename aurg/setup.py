from collections.abc import Callable
import shutil
import sys

from .baseline import default_baseline_path, write_baseline
from .config import Config, ConfigError, ConfigPaths, DEFAULT_MODEL, write_config_file, write_secrets_file
from .packages import fetch_packages, list_foreign_packages


InputFunc = Callable[[str], str]


WARNING = """\
aurg is an advisory scanner, not a security boundary.
Always review PKGBUILD and related build files manually before installing AUR packages.
AI can miss malicious behavior, misunderstand shell code, or produce false confidence.
"""


def run_setup(
    paths: ConfigPaths,
    input_func: InputFunc = input,
) -> Config:
    print(WARNING)

    aur_helper = choose_aur_helper(input_func)
    scan_mode = choose_scan_mode(input_func)
    provider = choose_provider(input_func)
    api_key = ask_api_key(provider, input_func)
    model = choose_model(provider, input_func)

    config = Config(
        aur_helper=aur_helper,
        scan_mode=scan_mode,
        provider=provider,
        model=model,
        require_ai=True,
        api_key=api_key,
        config_path=paths.config,
        secrets_path=paths.secrets,
    )

    write_config_file(paths.config, config)
    write_secrets_file(paths.secrets, provider, api_key)

    print(f"Wrote config: {paths.config}")
    print(f"Wrote secrets: {paths.secrets}")
    seed_update_baseline(config)
    return config


def seed_update_baseline(config: Config) -> None:
    packages = list_foreign_packages()
    if packages is None:
        print("Could not list installed foreign packages; skipped update baseline.", file=sys.stderr)
        return
    if not packages:
        print("No installed foreign packages found; skipped update baseline.")
        return

    fetched, failures = fetch_packages(packages, config.scan_mode)
    if fetched:
        write_baseline(fetched, config.scan_mode)
    for package, reason in failures.items():
        print(f"Baseline skipped {package}: {reason}", file=sys.stderr)

    print(
        f"Wrote update baseline: {default_baseline_path()} "
        f"({len(packages)} detected, {len(fetched)} recorded, {len(failures)} skipped)"
    )


def choose_aur_helper(input_func: InputFunc) -> str:
    installed = [name for name in ("yay", "paru") if shutil.which(name)]
    detail = f"installed: {', '.join(installed)}" if installed else "no supported helper detected"
    print(f"AUR helper ({detail})")
    return choose(
        input_func,
        "Select AUR helper",
        [
            ("auto", "auto, prefer yay then paru"),
            ("yay", "yay"),
            ("paru", "paru"),
        ],
        "auto",
    )


def choose_scan_mode(input_func: InputFunc) -> str:
    return choose(
        input_func,
        "Select scan mode",
        [
            ("full", "full, recommended"),
            ("pkgbuild", "pkgbuild only, faster"),
        ],
        "full",
    )


def choose_provider(input_func: InputFunc) -> str:
    provider = choose(
        input_func,
        "Select API provider",
        [
            ("google", "google, recommended"),
            ("openai", "openai, not implemented yet"),
            ("anthropic", "anthropic, not implemented yet"),
        ],
        "google",
    )
    if provider != "google":
        raise ConfigError(f"Provider not implemented yet: {provider}. Only google is supported in this version.")
    return provider


def ask_api_key(provider: str, input_func: InputFunc) -> str:
    prompt = "Enter Google API key: " if provider == "google" else f"Enter {provider} API key: "
    while True:
        try:
            api_key = input_func(prompt).strip()
        except EOFError as exc:
            raise ConfigError("Setup cancelled: API key input was not available") from exc
        if api_key:
            return api_key
        print("API key is required.")


def choose_model(provider: str, input_func: InputFunc) -> str:
    if provider != "google":
        raise ConfigError(f"Provider not implemented yet: {provider}. Only google is supported in this version.")

    try:
        answer = input_func(f"Model [{DEFAULT_MODEL}]: ").strip()
    except EOFError as exc:
        raise ConfigError("Setup cancelled: model input was not available") from exc
    return answer or DEFAULT_MODEL


def choose(input_func: InputFunc, title: str, options: list[tuple[str, str]], default: str) -> str:
    print(title)
    for index, (_, label) in enumerate(options, start=1):
        suffix = " [default]" if options[index - 1][0] == default else ""
        print(f"  {index}. {label}{suffix}")

    by_number = {str(index): value for index, (value, _) in enumerate(options, start=1)}
    by_value = {value: value for value, _ in options}
    valid = {**by_number, **by_value}

    while True:
        try:
            answer = input_func("> ").strip().lower()
        except EOFError as exc:
            raise ConfigError(f"Setup cancelled: {title.lower()} input was not available") from exc
        if not answer:
            return default
        selected = valid.get(answer)
        if selected:
            return selected
        print(f"Choose one of: {', '.join(valid)}")
