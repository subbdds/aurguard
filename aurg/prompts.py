from .models import BuildFile


SYSTEM_PROMPT = """You are a strict AUR build-file security reviewer.
Classify the provided numbered AUR build files as Safe, Review, or Dangerous.

Rules:
- Safe: no suspicious behavior found.
- Review: potentially risky or unusual behavior, but not clearly malicious.
- Dangerous: clearly unsafe or out-of-line PKGBUILD behavior.

Review examples include sha256sums=('SKIP'), eval, unexpected network calls, systemctl enable, cron/autostart changes, hidden install hooks, or unusual obfuscation.
Dangerous examples include curl/wget piped to sh/bash, base64 decode piped to shell, sudo/su/pkexec, chmod +s, unsafe rm -rf paths, or writes outside $pkgdir/$srcdir during package functions.

Return only JSON matching the provided schema. Use exact file names and 1-based line numbers from the input."""


def build_user_prompt(files: list[BuildFile]) -> str:
    blocks = []
    for file in files:
        numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(file.text.splitlines(), start=1))
        blocks.append(f"FILE: {file.name}\n{numbered}")
    return "\n\n".join(blocks)
