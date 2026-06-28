import argparse
from pathlib import Path

from .config import APP_NAME, DEFAULT_MODEL, configured_model
from .output import exit_code_for_verdict, print_result
from .scanner import scan_fake_pkgbuild, scan_local_pkgbuild
from .wrapper import install_package


def main() -> int:
    args = parse_args()

    if args.command == "scan":
        result = scan_local_pkgbuild(Path(args.path), args.model, args.no_ai)
        print_result(result)
        return exit_code_for_verdict(result.verdict)

    if args.command == "scanfake":
        result = scan_fake_pkgbuild(Path(args.path), args.model, args.no_ai)
        print_result(result)
        return exit_code_for_verdict(result.verdict)

    if args.sync_package:
        return install_package(args.sync_package, args.model, args.no_ai, args.force_dangerous)

    print("Nothing to do. Try: aurg -S package, aurg scan ./PKGBUILD, or aurg scanfake ./fake.PKGBUILD")
    return 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="A tiny yay/paru wrapper that scans an AUR PKGBUILD before installing.",
    )
    parser.add_argument("--no-ai", action="store_true", help="Use local fallback rules only.")
    parser.add_argument(
        "--force-dangerous",
        action="store_true",
        help="Allow install even when the scan returns Dangerous.",
    )
    parser.add_argument(
        "--model",
        default=configured_model(),
        help=f"Gemini model name. Default: {DEFAULT_MODEL}",
    )

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
