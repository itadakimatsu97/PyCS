from pathlib import Path


class ParsingFailed(Exception):
    def __init__(self, path: Path) -> None:
        self.path = path

    def __str__(self) -> str:
        return F'lief.parse failed at {self.path}'


class LibCNotFound(Exception):
    def __str__(self) -> str:
        return 'Finding LibC failed.'
