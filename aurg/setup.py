from collections.abc import Callable
import shutil
import subprocess
import sys

from .config import Config, ConfigError, ConfigPaths, DEFAULT_MODEL, resolve_api_key, write_config_file, write_secrets_file
from .errors import AurgError
from .fetch import fetch_build_files
from .state import load_state, save_state, update_baseline


InputFunc = Callable[[str], str]
MAX_BASELINE_FAILURE_SAMPLES = 5


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
    api_key = resolve_existing_api_key(provider, paths) or ask_api_key(provider, input_func)
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
    record_setup_baselines(config)

    print(f"Wrote config: {paths.config}")
    print(f"Wrote secrets: {paths.secrets}")
    return config


def resolve_existing_api_key(provider: str, paths: ConfigPaths) -> str | None:
    api_key = resolve_api_key(provider, paths.secrets)
    if api_key:
        print(f"Using existing {provider_label(provider)} API key.")
    return api_key


def provider_label(provider: str) -> str:
    return "Google" if provider == "google" else provider


def record_setup_baselines(config: Config) -> None:
    packages = list_installed_foreign_packages()
    if packages is None:
        print("Could not record installed AUR package baseline: pacman -Qqm failed.", file=sys.stderr)
        return
    if not packages:
        return

    state = load_state()
    recorded = 0
    failures: list[tuple[str, str]] = []
    total = len(packages)
    print(f"Recording installed AUR package baselines: 0/{total}", end="", flush=True)
    for index, package in enumerate(packages, start=1):
        try:
            files = fetch_build_files(package, config.scan_mode)
        except AurgError as exc:
            failures.append((package, str(exc)))
            print_baseline_progress(index, total, recorded, len(failures), package)
            continue
        update_baseline(state, package, files, "setup-installed")
        recorded += 1
        print_baseline_progress(index, total, recorded, len(failures), package)

    print()

    if recorded:
        save_state(state)
    skipped = len(failures)
    print(f"Baseline complete: recorded {recorded}/{total}; skipped {skipped}.")
    if skipped:
        print("Skipped packages are left untrusted until a later full scan or successful install.")
        for package, reason in failures[:MAX_BASELINE_FAILURE_SAMPLES]:
            print(f"  {package}: {reason}")
        remaining = skipped - MAX_BASELINE_FAILURE_SAMPLES
        if remaining > 0:
            print(f"  ...and {remaining} more.")


def print_baseline_progress(index: int, total: int, recorded: int, skipped: int, package: str) -> None:
    width = 24
    filled = int(width * index / total) if total else width
    bar = "#" * filled + "-" * (width - filled)
    suffix = f" ok={recorded} skipped={skipped} current={package}"
    print(f"\rRecording installed AUR package baselines: [{bar}] {index}/{total}{suffix}", end="", flush=True)


def list_installed_foreign_packages() -> list[str] | None:
    try:
        completed = subprocess.run(["pacman", "-Qqm"], check=False, capture_output=True, text=True)
    except OSError:
        return None
    if completed.returncode not in {0, 1}:
        return None
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


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
