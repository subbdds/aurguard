from pathlib import Path
import contextlib
import io
import os
import sys
import tempfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aurg.config import ConfigError, ConfigOverrides, ConfigPaths, load_config, uses_default_config_paths
from aurg.fetch import CgitTreeParser, should_scan_build_file
from aurg.models import BuildFile
from aurg.prompts import build_user_prompt
from aurg.scanner import read_local_build_files
from aurg.setup import run_setup
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


def test_setup_writes_config_and_secrets() -> None:
    with clean_config_env(), tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        paths = ConfigPaths(root / "config.toml", root / "secrets.env")
        answers = iter(["", "", "", "setup-secret", "gemini-custom"])

        with contextlib.redirect_stdout(io.StringIO()):
            run_setup(paths, input_func=lambda prompt: next(answers))
        config = load_config(paths.config, paths.secrets)

    assert config.aur_helper == "auto"
    assert config.scan_mode == "full"
    assert config.provider == "google"
    assert config.model == "gemini-custom"
    assert config.api_key == "setup-secret"


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
    test_setup_writes_config_and_secrets()
    test_default_config_path_detection()
