import argparse
from pathlib import Path
import sys

from .config import APP_NAME, DEFAULT_MODEL, ConfigError, ConfigOverrides, load_config
from .output import exit_code_for_verdict, print_result
from .scanner import scan_fake_pkgbuild, scan_local_pkgbuild
from .wrapper import install_package


def run() -> int:
    try:
        return main()
    except KeyboardInterrupt:
        print()
        return 130


def main() -> int:
    args = parse_args()
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

    if args.sync_package:
        return install_package(args.sync_package, config, args.no_ai, args.force_dangerous)

    print("Nothing to do. Try: aurg -S package, aurg scan ./PKGBUILD, or aurg scanfake ./fake.PKGBUILD")
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

    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", help="Scan a local PKGBUILD file or package folder.")
    scan_parser.add_argument("path")
    fake_parser = subparsers.add_parser("scanfake", help="Scan a standalone fake PKGBUILD file.")
    fake_parser.add_argument("path")

    parser.add_argument("-S", dest="sync_package", metavar="PACKAGE", help="Scan then install an AUR package.")

    args = parser.parse_args()
    if args.command and args.sync_package:
        parser.error("choose either a command or -S, not both")
    return args
