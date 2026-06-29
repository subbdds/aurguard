from .models import BuildFile, PackageBuild


SYSTEM_PROMPT = """You are a strict AUR build-file security reviewer.
Classify the provided numbered AUR build files as Safe, Review, or Dangerous.

Rules:
- Safe: no suspicious behavior found.
- Review: potentially risky or unusual behavior, but not clearly malicious.
- Dangerous: clearly unsafe or out-of-line PKGBUILD behavior.

Remember, everything is suspicious until proven safe. If something can even in theory be potentially harmful or dangerous, classify it as Review. Think your decision through.

Remember to be strict and conservative in your classification. If in doubt, classify as Review. This is a security review, and is very sensitive, remember that.

Keep the summary as brief as possible, but it should not affect your judgment.

Return only JSON matching the provided schema. Use exact file names and 1-based line numbers from the input."""


BATCH_SYSTEM_PROMPT = """You are a strict AUR build-file security reviewer.
Classify each provided AUR package as Safe, Review, or Dangerous.

Rules:
- Safe: no suspicious behavior found.
- Review: potentially risky or unusual behavior, but not clearly malicious.
- Dangerous: clearly unsafe or out-of-line PKGBUILD behavior.

Everything is suspicious until proven safe. If in doubt, classify that package as Review.
Return one result for every package. Keep summaries brief.
Return only JSON matching the provided schema. Use exact package names, file names, and 1-based line numbers from the input."""


def build_user_prompt(files: list[BuildFile]) -> str:
    blocks = []
    for file in files:
        numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(file.text.splitlines(), start=1))
        blocks.append(f"FILE: {file.name}\n{numbered}")
    return "\n\n".join(blocks)


def build_batch_user_prompt(packages: list[PackageBuild]) -> str:
    package_blocks = []
    for package in packages:
        file_blocks = []
        for file in package.files:
            numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(file.text.splitlines(), start=1))
            file_blocks.append(f"FILE: {file.name}\n{numbered}")
        package_blocks.append(f"PACKAGE: {package.name}\n" + "\n\n".join(file_blocks))
    return "\n\n---\n\n".join(package_blocks)
