import argparse
from pathlib import Path
import sys

from .config import (
    APP_NAME,
    DEFAULT_MODEL,
    ConfigError,
    ConfigOverrides,
    load_config,
    resolve_config_paths,
    uses_default_config_paths,
)
from .output import exit_code_for_verdict, print_result
from .scanner import scan_fake_pkgbuild, scan_local_pkgbuild
from .setup import rescan_update_baseline, run_setup
from .wrapper import run_helper_command


def run() -> int:
    try:
        return main()
    except KeyboardInterrupt:
        print()
        return 130


def main() -> int:
    args = parse_args()
    paths = resolve_config_paths(args.config, args.secrets)

    if args.command == "setup":
        try:
            run_setup(paths)
        except ConfigError as exc:
            print(f"Setup error: {exc}", file=sys.stderr)
            return 2
        return 0

    if uses_default_config_paths(args.config, args.secrets) and not paths.config.is_file():
        if not sys.stdin.isatty():
            print(f"No config found at {paths.config}. Run: aurg setup", file=sys.stderr)
            return 2
        print(f"No config found at {paths.config}. Starting first-run setup.")
        try:
            run_setup(paths)
        except ConfigError as exc:
            print(f"Setup error: {exc}", file=sys.stderr)
            return 2

    try:
        config = load_config(
            args.config,
            args.secrets,
            ConfigOverrides(
                aur_helper=args.aur_helper,
                scan_mode=args.scan_mode,
                model=args.model,
            ),
        )
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2

    if args.command == "scan":
        result = scan_local_pkgbuild(Path(args.path), config, args.no_ai)
        print_result(result)
        return exit_code_for_verdict(result.verdict)

    if args.command == "scanfake":
        result = scan_fake_pkgbuild(Path(args.path), config, args.no_ai)
        print_result(result)
        return exit_code_for_verdict(result.verdict)

    if args.command == "rescan":
        return 0 if rescan_update_baseline(config) else 1

    if args.helper_args:
        return run_helper_command(args.helper_args, config, args.no_ai, args.force_dangerous)

    print("Nothing to do. For setup run: aurg setup" \
    "\n> use as you would your AUR helper with arguments like -S, -Syu" \
    "\n> to rescan installed packages: aurg rescan")
    return 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="A tiny yay/paru wrapper that scans an AUR PKGBUILD before installing.",
    )
    parser.add_argument("--config", help="Path to config.toml. Default: ~/.config/aurg/config.toml")
    parser.add_argument("--secrets", help="Path to secrets.env. Default: ~/.config/aurg/secrets.env")
    parser.add_argument("--no-ai", action="store_true", help="Use local fallback rules only.")
    parser.add_argument(
        "--force-dangerous",
        action="store_true",
        help="Allow install even when the scan returns Dangerous.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=f"Gemini model name. Default: {DEFAULT_MODEL}",
    )
    parser.add_argument("--scan-mode", choices=("full", "pkgbuild"), help="Files to scan. Default: config value.")
    parser.add_argument("--aur-helper", choices=("auto", "yay", "paru"), help="AUR helper to run. Default: config value.")

    args, remaining = parser.parse_known_args()
    args.command = None
    args.path = None
    args.helper_args = []

    if remaining:
        command = remaining[0]
        if command == "setup":
            if len(remaining) > 1:
                parser.error("setup does not accept extra arguments")
            args.command = "setup"
        elif command == "rescan":
            if len(remaining) > 1:
                parser.error("rescan does not accept extra arguments")
            args.command = "rescan"
        elif command in {"scan", "scanfake"}:
            if len(remaining) != 2:
                parser.error(f"{command} requires exactly one path")
            args.command = command
            args.path = remaining[1]
        else:
            args.helper_args = remaining
    return args
