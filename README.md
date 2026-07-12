# aurg

`aurg` is a small `yay`/`paru` wrapper that scans AUR build files before installation.

## Install on Arch Linux

Clone the repository and build an Arch package with `makepkg`:

```bash
git clone https://github.com/subbdds/aurguard.git
cd aurguard
makepkg -si
```

This installs the `aurguard-git` package through pacman and makes the `aurg`
command available system-wide:

```bash
aurg setup
aurg --help
aurg -S package-name
```

Build dependencies listed in `PKGBUILD` must be installed first. On a standard
Arch system, `makepkg -s` asks pacman to install any that are missing.
It fetches the package's AUR files, asks an AI model to review them when configured,
falls back to local static rules when AI is disabled or unavailable, and then decides
whether to continue, prompt for review, or block installation.

This tool is advisory only. It is not a sandbox, verifier, or security boundary.
Always review `PKGBUILD` and related build files yourself before installing AUR
packages.

## What it scans

By default, `aurg` uses full scan mode and reviews scan-relevant files from the AUR
tree:

- `PKGBUILD`
- `.SRCINFO`
- `*.install`
- `*.patch`
- `*.diff`
- `*.sh`
- `*.service`
- `*.timer`
- `*.desktop`

Use `pkgbuild` scan mode to scan only `PKGBUILD`.

## Requirements

- Python 3.11 or newer
- `yay` or `paru` for package installation
- A Google Gemini API key for AI scanning

Only the Google provider is implemented at the moment. `openai` and `anthropic`
are recognized config values but rejected until support is added.

## Quick start

Run the first-time setup:

```sh
python -m aurg setup
```

If a key already exists in the secrets file or environment, setup still prompts
for one; leave the field empty to keep the existing key.

Setup writes:

- `~/.config/aurg/config.toml`
- `~/.config/aurg/secrets.env`

It also records currently installed foreign packages as an update baseline under
`~/.local/state/aurg/packages.json` without AI scanning them. Later system
updates scan only packages whose AUR build files changed from that baseline.
Packages that return AUR HTTP 404 or 429 while establishing or checking the
baseline are marked unavailable in the same file and skipped on later baseline
checks.

Baseline and update checks fetch AUR repository snapshots, not built packages or
upstream `source=...` files. Snapshot downloads are capped and only
scan-relevant build files are extracted in memory. Fetches run concurrently with
a small request pacer to avoid recreating AUR rate-limit bursts.
Before downloading snapshots, update checks query batched AUR RPC metadata and
skip packages whose `LastModified` timestamp still matches the baseline.

Then scan and install an AUR package:

```sh
python -m aurg -S package-name
```

You can also run the executable wrapper directly from this repository:

```sh
./main.py -S package-name
```

## Commands

Scan and install an AUR package:

```sh
python -m aurg -S package-name
```

Scan a local `PKGBUILD` file or a package directory:

```sh
python -m aurg scan ./PKGBUILD
python -m aurg scan ./package-directory
```

Scan a standalone fake or test `PKGBUILD` file:

```sh
python -m aurg scanfake ./fake.PKGBUILD
```

Run without AI and use local fallback rules only:

```sh
python -m aurg --no-ai scan ./package-directory
```

Rebuild the installed-package update baseline, including packages previously
marked unavailable:

```sh
python -m aurg rescan
```

Allow installation even when the scan verdict is `Dangerous`:

```sh
python -m aurg --force-dangerous -S package-name
```

## Configuration

Default config path:

```text
~/.config/aurg/config.toml
```

Example:

```toml
aur_helper = "auto"
scan_mode = "full"
provider = "google"
model = "gemini-3.1-flash-lite"
require_ai = true
max_update_requests = 4
```

Supported values:

- `aur_helper`: `auto`, `yay`, or `paru`
- `scan_mode`: `full` or `pkgbuild`
- `provider`: currently only `google` is implemented
- `model`: Gemini model name
- `require_ai`: `true` to return a `Review` verdict when AI is unavailable
- `max_update_requests`: maximum AI request fragments for one system-wide
  update scan

Default secrets path:

```text
~/.config/aurg/secrets.env
```

Example:

```env
GEMINI_API_KEY="your-api-key"
```

`GOOGLE_API_KEY` is also accepted.

Long-running baseline fetches and grouped update scans show a single-line
progress indicator in interactive terminals. The indicator is redrawn in place
and cleared when the step finishes.

## Overrides

Use alternate config or secrets files:

```sh
python -m aurg --config ./configs/config.toml --secrets ./configs/secrets.env scan ./PKGBUILD
```

Override settings with environment variables:

```sh
AURG_AUR_HELPER=paru \
AURG_SCAN_MODE=pkgbuild \
AURG_MODEL=gemini-3.1-flash-lite \
AURG_MAX_UPDATE_REQUESTS=4 \
python -m aurg -S package-name
```

Supported environment variables:

- `AURG_CONFIG_FILE`
- `AURG_SECRETS_FILE`
- `AURG_AUR_HELPER`
- `AURG_SCAN_MODE`
- `AURG_PROVIDER`
- `AURG_MODEL`
- `AURG_REQUIRE_AI`
- `AURG_MAX_UPDATE_REQUESTS`
- `GEMINI_API_KEY`
- `GOOGLE_API_KEY`

Command-line options such as `--model`, `--scan-mode`, and `--aur-helper` override
the config file for that run.

## Verdicts

- `Safe`: no suspicious behavior was found
- `Review`: installation requires manual confirmation or AI was unavailable
- `Dangerous`: installation is blocked unless `--force-dangerous` is used

Local fallback rules look for high-risk shell patterns such as remote script
execution, privilege escalation, setuid/setgid changes, broad destructive deletes,
unpinned source integrity, `eval`, network activity, systemd enablement, and
autostart or cron behavior.

## Development

Run the lightweight test file directly:

```sh
python tests/test_full_file_scanning.py
```

The project currently has no packaging metadata, so the most reliable development
entry points are:

```sh
python -m aurg --help
./main.py --help
```
