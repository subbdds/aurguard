# aurg

`aurg` wraps `yay` or `paru` and scans AUR build files before installation. It uses local rules and, by default, Google Gemini (as the only provider available). Packages classified as dangerous are blocked unless explicitly allowed.

It is an advisory tool, not a security boundary. Review AUR build files before installing them.

## Install

Requires Python 3.11 or later and either `yay` or `paru`.

```sh
makepkg -si
aurg setup
```

Setup writes configuration to `~/.config/aurg/` and asks for a Google API key.

## Usage

Pass AUR-helper arguments directly:

```sh
aurg -S package-name
aurg -Syu
```

Other commands:

```sh
aurg scan ./PKGBUILD
aurg rescan
aurg --help
```

Use `--no-ai` to scan with local rules only.
