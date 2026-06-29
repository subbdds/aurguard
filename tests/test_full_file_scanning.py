from pathlib import Path
import contextlib
import io
import os
import sys
import tempfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aurg.config import Config, ConfigError, ConfigOverrides, ConfigPaths, load_config, uses_default_config_paths
from aurg.baseline import compare_to_baseline, load_baseline, write_baseline
from aurg.fetch import CgitTreeParser, should_scan_build_file
from aurg.ai_client import validate_batch_ai_result
from aurg.models import BuildFile, PackageBuild, PackageScanResult, ScanResult
from aurg.prompts import build_batch_user_prompt, build_user_prompt
from aurg.scanner import read_local_build_files, split_evenly
from aurg.setup import run_setup
from aurg.wrapper import classify_helper_args, scan_full_system_update
import aurg.setup as setup
import aurg.wrapper as wrapper


def test_scan_file_matching() -> None:
    included = [
        "PKGBUILD",
        ".SRCINFO",
        "foo.install",
        "fix.patch",
        "changes.diff",
        "script.sh",
        "units/app.service",
        "units/app.timer",
        "app.desktop",
    ]
    excluded = ["README.md", "src/main.py", "notes.service.md"]

    for path in included:
        assert should_scan_build_file(path), path
    for path in excluded:
        assert not should_scan_build_file(path), path


def test_cgit_tree_parser() -> None:
    parser = CgitTreeParser()
    parser.feed(
        """
        <a class="ls-blob" href="/cgit/aur.git/tree/PKGBUILD?h=demo">PKGBUILD</a>
        <a class="ls-blob" href="/cgit/aur.git/tree/.SRCINFO?h=demo">.SRCINFO</a>
        <a class="ls-dir" href="/cgit/aur.git/tree/systemd?h=demo">systemd</a>
        <a class="ls-blob" href="/cgit/aur.git/tree/../evil?h=demo">evil</a>
        <a class="ls-blob" href="/cgit/aur.git/plain/not-tree?h=demo">not-tree</a>
        """
    )

    assert parser.files == {"PKGBUILD", ".SRCINFO"}
    assert parser.dirs == {"systemd"}


def test_prompt_contains_multiple_files() -> None:
    prompt = build_user_prompt(
        [
            BuildFile("PKGBUILD", "pkgname=demo"),
            BuildFile("demo.install", "post_install() {\n  true\n}"),
        ]
    )

    assert "FILE: PKGBUILD\n1: pkgname=demo" in prompt
    assert "FILE: demo.install\n1: post_install() {" in prompt
    assert "2:   true" in prompt


def test_batch_prompt_contains_package_boundaries() -> None:
    prompt = build_batch_user_prompt(
        [
            PackageBuild("alpha", [BuildFile("PKGBUILD", "pkgname=alpha")]),
            PackageBuild("beta", [BuildFile("PKGBUILD", "pkgname=beta")]),
        ]
    )

    assert "PACKAGE: alpha" in prompt
    assert "FILE: PKGBUILD\n1: pkgname=alpha" in prompt
    assert "PACKAGE: beta" in prompt


def test_local_build_file_collection() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        (root / "PKGBUILD").write_text("pkgname=demo\n", encoding="utf-8")
        (root / ".SRCINFO").write_text("pkgbase = demo\n", encoding="utf-8")
        (root / "demo.install").write_text("post_install() { true; }\n", encoding="utf-8")
        (root / "README.md").write_text("ignored\n", encoding="utf-8")
        (root / "units").mkdir()
        (root / "units" / "demo.service").write_text("[Service]\n", encoding="utf-8")

        files = read_local_build_files(root)

    assert [file.name for file in files] == [
        "PKGBUILD",
        ".SRCINFO",
        "demo.install",
        "units/demo.service",
    ]


def test_pkgbuild_scan_mode_only_reads_pkgbuild() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        (root / "PKGBUILD").write_text("pkgname=demo\n", encoding="utf-8")
        (root / "demo.install").write_text("post_install() { true; }\n", encoding="utf-8")

        files = read_local_build_files(root, "pkgbuild")

    assert [file.name for file in files] == ["PKGBUILD"]


def test_config_and_secrets_override_paths() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        config_path = root / "config.toml"
        secrets_path = root / "secrets.env"
        config_path.write_text(
            """
aur_helper = "paru"
scan_mode = "pkgbuild"
provider = "google"
model = "gemini-test"
require_ai = true
""".strip(),
            encoding="utf-8",
        )
        secrets_path.write_text("GEMINI_API_KEY='secret-value'\n", encoding="utf-8")

        config = load_config(config_path, secrets_path, ConfigOverrides(model="gemini-cli"))

    assert config.aur_helper == "paru"
    assert config.scan_mode == "pkgbuild"
    assert config.provider == "google"
    assert config.model == "gemini-cli"
    assert config.api_key == "secret-value"


def test_config_reads_max_update_requests() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "config.toml"
        config_path.write_text("max_update_requests = 6\n", encoding="utf-8")
        os.environ["AURG_MAX_UPDATE_REQUESTS"] = "3"

        config = load_config(config_path, Path(temp_dir) / "secrets.env")

    assert config.max_update_requests == 3


def test_config_rejects_unimplemented_provider() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "config.toml"
        config_path.write_text('provider = "openai"\n', encoding="utf-8")

        try:
            load_config(config_path, Path(temp_dir) / "secrets.env")
        except ConfigError as exc:
            assert "Provider not implemented yet" in str(exc)
        else:
            raise AssertionError("openai provider should be rejected until implemented")


def test_aur_helper_selection() -> None:
    original_which = wrapper.shutil.which
    try:
        wrapper.shutil.which = lambda name: f"/usr/bin/{name}" if name == "paru" else None

        assert wrapper.find_aur_helper("auto") == "/usr/bin/paru"
        assert wrapper.find_aur_helper("paru") == "/usr/bin/paru"
        assert wrapper.find_aur_helper("yay") is None
    finally:
        wrapper.shutil.which = original_which


def test_helper_arg_classification() -> None:
    remove = classify_helper_args(["-Rns", "demo"])
    assert not remove.scan

    search = classify_helper_args(["-Ss", "demo"])
    assert not search.scan

    refresh = classify_helper_args(["-Sy"])
    assert not refresh.scan

    refresh_install = classify_helper_args(["-Sy", "demo"])
    assert refresh_install.scan
    assert not refresh_install.scan_updates
    assert refresh_install.packages == ["demo"]

    double_refresh = classify_helper_args(["-Syy"])
    assert not double_refresh.scan

    download_only = classify_helper_args(["-Sw", "demo"])
    assert not download_only.scan

    long_download_only = classify_helper_args(["--sync", "--downloadonly", "demo"])
    assert not long_download_only.scan

    install = classify_helper_args(["-S", "--needed", "demo"])
    assert install.scan
    assert not install.scan_updates
    assert install.packages == ["demo"]

    long_install = classify_helper_args(["--sync", "demo"])
    assert long_install.scan
    assert not long_install.scan_updates
    assert long_install.packages == ["demo"]

    update = classify_helper_args(["-Syu"])
    assert update.scan
    assert update.scan_updates
    assert update.packages == []

    long_update = classify_helper_args(["--sync", "--refresh", "--sysupgrade"])
    assert long_update.scan
    assert long_update.scan_updates
    assert long_update.packages == []

    update_with_target = classify_helper_args(["-Syu", "demo"])
    assert update_with_target.scan
    assert update_with_target.scan_updates
    assert update_with_target.packages == ["demo"]


def test_baseline_round_trip_and_compare() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "packages.json"
        files = {"demo": [BuildFile("PKGBUILD", "pkgname=demo\n")]}
        write_baseline(files, "full", path)

        baseline = load_baseline(path)
        same = compare_to_baseline(files, baseline)
        changed = compare_to_baseline({"demo": [BuildFile("PKGBUILD", "pkgname=demo\npkgver=2\n")]}, baseline)
        missing = compare_to_baseline({"new": [BuildFile("PKGBUILD", "pkgname=new\n")]}, baseline)

    assert same.unchanged == ["demo"]
    assert same.changed == []
    assert [package.name for package in changed.changed] == ["demo"]
    assert [package.name for package in missing.changed] == ["new"]


def test_split_evenly_limits_group_count() -> None:
    packages = [PackageBuild(str(index), [BuildFile("PKGBUILD", "")]) for index in range(10)]

    groups = split_evenly(packages, 4)

    assert [len(group) for group in groups] == [3, 3, 2, 2]


def test_batch_ai_response_validation() -> None:
    packages = [
        PackageBuild("demo", [BuildFile("PKGBUILD", "pkgname=demo\ncurl https://example.test\n")]),
        PackageBuild("safe", [BuildFile("PKGBUILD", "pkgname=safe\n")]),
    ]

    results = validate_batch_ai_result(
        {
            "results": [
                {
                    "package": "demo",
                    "verdict": "Review",
                    "summary": "Network use.",
                    "findings": [{"file": "PKGBUILD", "line": 2, "severity": "Review", "reason": "Downloads content."}],
                },
                {"package": "safe", "verdict": "Safe", "summary": "Clean.", "findings": []},
            ]
        },
        packages,
    )

    assert [result.package for result in results] == ["demo", "safe"]
    assert results[0].result.findings[0].text == "curl https://example.test"


def test_full_update_scans_only_changed_baseline_packages() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        os.environ["XDG_STATE_HOME"] = str(root / "state")
        write_baseline({"same": [BuildFile("PKGBUILD", "pkgname=same\n")]}, "full")
        fetched = {
            "same": [BuildFile("PKGBUILD", "pkgname=same\n")],
            "changed": [BuildFile("PKGBUILD", "pkgname=changed\n")],
        }
        scanned = []
        original_list_foreign = wrapper.list_foreign_packages
        original_fetch_packages = wrapper.fetch_packages
        original_scan_package_groups = wrapper.scan_package_groups

        try:
            wrapper.list_foreign_packages = lambda: ["same", "changed"]
            wrapper.fetch_packages = lambda packages, scan_mode: (fetched, {})

            def fake_scan_package_groups(packages, config, no_ai=False):
                scanned.extend(package.name for package in packages)
                return [
                    PackageScanResult(
                        package.name,
                        ScanResult("Safe", [], "Clean.", "ai", ""),
                    )
                    for package in packages
                ]

            wrapper.scan_package_groups = fake_scan_package_groups
            with contextlib.redirect_stdout(io.StringIO()):
                result = scan_full_system_update(Config(), no_ai=False)
        finally:
            wrapper.list_foreign_packages = original_list_foreign
            wrapper.fetch_packages = original_fetch_packages
            wrapper.scan_package_groups = original_scan_package_groups

    assert result == fetched
    assert scanned == ["changed"]


def test_setup_writes_config_and_secrets() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        paths = ConfigPaths(root / "config.toml", root / "secrets.env")
        answers = iter(["", "", "", "setup-secret", "gemini-custom"])
        original_list_foreign = setup.list_foreign_packages

        try:
            setup.list_foreign_packages = lambda: []
            with contextlib.redirect_stdout(io.StringIO()):
                run_setup(paths, input_func=lambda prompt: next(answers))
            config = load_config(paths.config, paths.secrets)
        finally:
            setup.list_foreign_packages = original_list_foreign

    assert config.aur_helper == "auto"
    assert config.scan_mode == "full"
    assert config.provider == "google"
    assert config.model == "gemini-custom"
    assert config.api_key == "setup-secret"


def test_setup_seeds_baseline_with_mocked_packages() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        os.environ["XDG_STATE_HOME"] = str(root / "state")
        paths = ConfigPaths(root / "config.toml", root / "secrets.env")
        answers = iter(["", "", "", "setup-secret", ""])
        original_list_foreign = setup.list_foreign_packages
        original_fetch_packages = setup.fetch_packages

        try:
            setup.list_foreign_packages = lambda: ["demo", "stale"]
            setup.fetch_packages = lambda packages, scan_mode: (
                {"demo": [BuildFile("PKGBUILD", "pkgname=demo\n")]},
                {"stale": "not found"},
            )
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                run_setup(paths, input_func=lambda prompt: next(answers))
            baseline = load_baseline(root / "state" / "aurg" / "packages.json")
        finally:
            setup.list_foreign_packages = original_list_foreign
            setup.fetch_packages = original_fetch_packages

    assert sorted(baseline["packages"]) == ["demo"]


def test_default_config_path_detection() -> None:
    with clean_config_env():
        assert uses_default_config_paths()
        assert not uses_default_config_paths("configs/config.toml", None)
        os.environ["AURG_CONFIG_FILE"] = "configs/config.toml"
        assert not uses_default_config_paths()


class clean_config_env:
    KEYS = (
        "AURG_CONFIG_FILE",
        "AURG_SECRETS_FILE",
        "AURG_AUR_HELPER",
        "AURG_SCAN_MODE",
        "AURG_PROVIDER",
        "AURG_MODEL",
        "AURG_REQUIRE_AI",
        "AURG_MAX_UPDATE_REQUESTS",
        "XDG_STATE_HOME",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    )

    def __enter__(self) -> None:
        self.original = {key: os.environ.get(key) for key in self.KEYS}
        for key in self.KEYS:
            os.environ.pop(key, None)

    def __exit__(self, exc_type, exc, tb) -> None:
        for key, value in self.original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == "__main__":
    test_scan_file_matching()
    test_cgit_tree_parser()
    test_prompt_contains_multiple_files()
    test_batch_prompt_contains_package_boundaries()
    test_local_build_file_collection()
    test_pkgbuild_scan_mode_only_reads_pkgbuild()
    test_config_and_secrets_override_paths()
    test_config_reads_max_update_requests()
    test_config_rejects_unimplemented_provider()
    test_aur_helper_selection()
    test_helper_arg_classification()
    test_baseline_round_trip_and_compare()
    test_split_evenly_limits_group_count()
    test_batch_ai_response_validation()
    test_full_update_scans_only_changed_baseline_packages()
    test_setup_writes_config_and_secrets()
    test_setup_seeds_baseline_with_mocked_packages()
    test_default_config_path_detection()
