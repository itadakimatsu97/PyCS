from typing import Iterator, List
from pathlib import Path
import os

ignore = ('.ko', '.o', '.dex', '.odex', '.oat')


def getListOfFiles(listOfFilePath: List[Path], recursive: bool = False) -> Iterator[Path]:
    for path in listOfFilePath:
        if path.is_symlink():
            continue
        if path.is_dir():
            for dirEntry in os.scandir(path):
                if recursive:
                    yield from getListOfFiles([Path(dirEntry)], recursive)
                elif dirEntry.is_file():
                    yield Path(dirEntry)
        elif path.is_file():
            if not str(path).endswith(ignore):
                yield path
