import sys


class Progress:
    def __init__(self, label: str, total: int) -> None:
        self.label = label
        self.total = total
        self.current = 0
        self.enabled = total > 0 and sys.stderr.isatty()

    def __enter__(self) -> "Progress":
        self.render()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.finish()

    def advance(self) -> None:
        self.current += 1
        self.render()

    def render(self) -> None:
        if not self.enabled:
            return
        message = f"{self.label}: {self.current}/{self.total}"
        sys.stderr.write("\r" + message)
        sys.stderr.flush()

    def finish(self) -> None:
        if not self.enabled:
            return
        sys.stderr.write("\r" + " " * (len(self.label) + 20) + "\r")
        sys.stderr.flush()
