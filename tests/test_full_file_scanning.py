from pathlib import Path
import contextlib
import io
import os
import sys
import tempfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aurg.ai_client import validate_update_ai_result
from aurg.config import Config, ConfigError, ConfigOverrides, ConfigPaths, load_config, uses_default_config_paths
from aurg.fetch import CgitTreeParser, should_scan_build_file
from aurg.models import BuildFile, UpdatePackageInput
from aurg.prompts import build_user_prompt
from aurg.scanner import read_local_build_files
from aurg.state import PackageBaseline, PackageState, StoredBuildFile, hash_text, load_state, save_state
from aurg.setup import run_setup
from aurg.update_scan import build_update_input, split_evenly
from aurg.wrapper import AurUpdate, classify_helper_args, run_scanned_helper_command, scan_update_candidates
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
    assert config.update_ai_max_requests == 4


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


def test_setup_writes_config_and_secrets() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        paths = ConfigPaths(root / "config.toml", root / "secrets.env")
        answers = iter(["", "", "", "setup-secret", "gemini-custom"])
        original_list = setup.list_installed_foreign_packages

        try:
            setup.list_installed_foreign_packages = lambda: []
            with contextlib.redirect_stdout(io.StringIO()):
                run_setup(paths, input_func=lambda prompt: next(answers))
        finally:
            setup.list_installed_foreign_packages = original_list
        config = load_config(paths.config, paths.secrets)

    assert config.aur_helper == "auto"
    assert config.scan_mode == "full"
    assert config.provider == "google"
    assert config.model == "gemini-custom"
    assert config.api_key == "setup-secret"
    assert config.update_ai_max_requests == 4


def test_setup_records_installed_package_baselines() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        os.environ["XDG_STATE_HOME"] = str(root / "state")
        paths = ConfigPaths(root / "config.toml", root / "secrets.env")
        answers = iter(["", "", "", "setup-secret", "gemini-custom"])
        original_list = setup.list_installed_foreign_packages
        original_fetch = setup.fetch_build_files
        try:
            setup.list_installed_foreign_packages = lambda: ["demo"]
            setup.fetch_build_files = lambda package, scan_mode: [BuildFile("PKGBUILD", f"pkgname={package}\n")]
            with contextlib.redirect_stdout(io.StringIO()):
                run_setup(paths, input_func=lambda prompt: next(answers))
            state = load_state()
        finally:
            setup.list_installed_foreign_packages = original_list
            setup.fetch_build_files = original_fetch

    assert state.packages["demo"].baseline_reason == "setup-installed"
    assert state.packages["demo"].files["PKGBUILD"].text == "pkgname=demo\n"


def test_unchanged_update_package_skips_ai() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        os.environ["XDG_STATE_HOME"] = str(Path(temp_dir) / "state")
        files = [BuildFile("PKGBUILD", "pkgname=demo\n")]
        state = PackageState(
            {
                "demo": PackageBaseline(
                    "demo",
                    "setup-installed",
                    None,
                    {"PKGBUILD": StoredBuildFile(hash_text(files[0].text), files[0].text)},
                )
            }
        )
        save_state(state)
        original_fetch = wrapper.fetch_build_files
        original_scan_updates = wrapper.scan_update_packages
        called = {"ai": False}
        try:
            wrapper.fetch_build_files = lambda package, scan_mode: files
            wrapper.scan_update_packages = lambda packages, config, no_ai=False: called.__setitem__("ai", True)
            with contextlib.redirect_stdout(io.StringIO()):
                result = scan_update_candidates([AurUpdate("demo", "1", "2")], Config(api_key="key"), False, False)
        finally:
            wrapper.fetch_build_files = original_fetch
            wrapper.scan_update_packages = original_scan_updates

    assert result == {"demo": files}
    assert not called["ai"]


def test_changed_update_package_builds_diff_input() -> None:
    baseline = PackageBaseline(
        "demo",
        "setup-installed",
        "1-1",
        {"PKGBUILD": StoredBuildFile(hash_text("pkgname=demo\npkgver=1\n"), "pkgname=demo\npkgver=1\n")},
    )

    update_input = build_update_input("demo", baseline, [BuildFile("PKGBUILD", "pkgname=demo\npkgver=2\n")], "2-1")

    assert update_input.name == "demo"
    assert update_input.new_version == "2-1"
    assert update_input.files[0].name == "PKGBUILD"
    assert "-pkgver=1" in update_input.files[0].text
    assert "+pkgver=2" in update_input.files[0].text


def test_update_fragmentation_splits_packages_evenly() -> None:
    packages = [UpdatePackageInput(f"pkg{i}", None, None, "setup-installed", [BuildFile("PKGBUILD", "diff")], []) for i in range(40)]

    batches = split_evenly(packages, 4)

    assert [len(batch) for batch in batches] == [10, 10, 10, 10]


def test_update_fragmentation_uses_needed_request_count() -> None:
    packages = [UpdatePackageInput(f"pkg{i}", None, None, "setup-installed", [BuildFile("PKGBUILD", "diff")], []) for i in range(3)]

    batches = split_evenly(packages, 4)

    assert [len(batch) for batch in batches] == [1, 1, 1]


def test_update_ai_result_aggregation_uses_worst_verdict() -> None:
    packages = [
        UpdatePackageInput("safe-pkg", None, None, "setup-installed", [BuildFile("PKGBUILD", "diff")], [BuildFile("PKGBUILD", "pkgname=safe-pkg")]),
        UpdatePackageInput("review-pkg", None, None, "setup-installed", [BuildFile("PKGBUILD", "diff")], [BuildFile("PKGBUILD", "pkgname=review-pkg")]),
    ]

    result = validate_update_ai_result(
        {
            "packages": [
                {"name": "safe-pkg", "verdict": "Safe", "findings": [], "summary": "ok"},
                {
                    "name": "review-pkg",
                    "verdict": "Review",
                    "findings": [{"file": "PKGBUILD", "line": 1, "severity": "Review", "reason": "changed source"}],
                    "summary": "check",
                },
            ]
        },
        packages,
    )

    assert result.verdict == "Review"
    assert [package.verdict for package in result.packages] == ["Safe", "Review"]


def test_state_is_written_only_after_successful_helper_run() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        os.environ["XDG_STATE_HOME"] = str(Path(temp_dir) / "state")
        files = [BuildFile("PKGBUILD", "pkgname=demo\n")]
        original_find = wrapper.find_aur_helper
        original_scan = wrapper.scan_packages
        original_run = wrapper.run_helper
        try:
            wrapper.find_aur_helper = lambda preference: "/usr/bin/yay"
            wrapper.scan_packages = lambda packages, config, no_ai=False, force_dangerous=False: {"demo": files}
            wrapper.run_helper = lambda args, config, helper=None: 1
            assert run_scanned_helper_command(["-S", "demo"], ["demo"], False, Config(), False, False) == 1
            assert "demo" not in load_state().packages

            wrapper.run_helper = lambda args, config, helper=None: 0
            assert run_scanned_helper_command(["-S", "demo"], ["demo"], False, Config(), False, False) == 0
            assert load_state().packages["demo"].baseline_reason == "scanned-install"
        finally:
            wrapper.find_aur_helper = original_find
            wrapper.scan_packages = original_scan
            wrapper.run_helper = original_run


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
        "AURG_UPDATE_AI_MAX_REQUESTS",
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
    test_local_build_file_collection()
    test_pkgbuild_scan_mode_only_reads_pkgbuild()
    test_config_and_secrets_override_paths()
    test_config_rejects_unimplemented_provider()
    test_aur_helper_selection()
    test_helper_arg_classification()
    test_setup_writes_config_and_secrets()
    test_setup_records_installed_package_baselines()
    test_unchanged_update_package_skips_ai()
    test_changed_update_package_builds_diff_input()
    test_update_fragmentation_splits_packages_evenly()
    test_update_fragmentation_uses_needed_request_count()
    test_update_ai_result_aggregation_uses_worst_verdict()
    test_state_is_written_only_after_successful_helper_run()
    test_default_config_path_detection()
