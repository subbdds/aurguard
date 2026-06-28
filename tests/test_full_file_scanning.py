from pathlib import Path
import sys
import tempfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aurg.fetch import CgitTreeParser, should_scan_build_file
from aurg.models import BuildFile
from aurg.prompts import build_user_prompt
from aurg.scanner import read_local_build_files


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


if __name__ == "__main__":
    test_scan_file_matching()
    test_cgit_tree_parser()
    test_prompt_contains_multiple_files()
    test_local_build_file_collection()
