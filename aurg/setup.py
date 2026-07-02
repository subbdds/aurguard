from collections.abc import Callable
from collections import defaultdict
import shutil
import sys

from .baseline import default_baseline_path, merge_baseline, unavailable_from_failures, unavailable_packages
from .aur_rpc import fetch_package_info
from .config import Config, ConfigError, ConfigPaths, DEFAULT_MODEL, resolve_api_key, write_config_file, write_secrets_file
from .errors import AurgError
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
    existing_api_key = resolve_api_key(provider, paths.secrets)
    api_key = ask_api_key(provider, input_func, existing_api_key)
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
    rescan_update_baseline(config)
    return config


def rescan_update_baseline(config: Config, skip_unavailable: bool = False) -> bool:
    packages = list_foreign_packages()
    if packages is None:
        print("Could not list installed foreign packages; skipped update baseline.", file=sys.stderr)
        return False
    if not packages:
        print("No installed foreign packages found; skipped update baseline.")
        return True

    skipped = sorted(unavailable_packages().intersection(packages)) if skip_unavailable else []
    packages_to_check = [package for package in packages if package not in set(skipped)]
    try:
        metadata, failures = fetch_package_info(packages_to_check)
    except AurgError as exc:
        print(f"Could not query AUR metadata; skipped update baseline: {exc}", file=sys.stderr)
        return False

    package_bases = {package: info.package_base for package, info in metadata.items()}
    fetched, fetch_failures = fetch_packages(list(metadata), config.scan_mode, "Establishing update baseline", package_bases)
    failures.update(fetch_failures)
    unavailable = unavailable_from_failures(failures)
    if fetched or unavailable:
        fetched_metadata = {package: metadata[package] for package in fetched if package in metadata}
        merge_baseline(fetched, config.scan_mode, unavailable=unavailable, metadata=fetched_metadata)
    print_failure_summary("Baseline skipped", failures)

    print(
        f"Wrote update baseline: {default_baseline_path()} "
        f"({len(packages)} detected, {len(fetched)} recorded, {len(skipped) + len(failures)} skipped)"
    )
    return True


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


def ask_api_key(provider: str, input_func: InputFunc, existing_api_key: str | None = None) -> str:
    base_prompt = "Enter Google API key" if provider == "google" else f"Enter {provider} API key"
    prompt = f"{base_prompt} [keep existing]: " if existing_api_key else f"{base_prompt}: "
    while True:
        try:
            api_key = input_func(prompt).strip()
        except EOFError as exc:
            raise ConfigError("Setup cancelled: API key input was not available") from exc
        if api_key:
            return api_key
        if existing_api_key:
            return existing_api_key
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


def print_failure_summary(prefix: str, failures: dict[str, str]) -> None:
    if not failures:
        return
    by_reason: dict[str, list[str]] = defaultdict(list)
    for package, reason in failures.items():
        by_reason[reason].append(package)

    for reason, packages in sorted(by_reason.items(), key=lambda item: (-len(item[1]), item[0])):
        shown = ", ".join(packages[:6])
        extra = f", +{len(packages) - 6} more" if len(packages) > 6 else ""
        print(f"{prefix} {len(packages)} package(s): {reason} ({shown}{extra})", file=sys.stderr)
