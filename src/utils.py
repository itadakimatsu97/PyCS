#!/usr/bin/env python3
from typing import Iterator, List, Optional, Union
from pathlib import Path
import os

def getListOfFiles(listOfFilePath: List[Path], recursive: bool = False) -> Iterator[Path]:
    for path in listOfFilePath:
        # print(path.is_dir())
        if path.is_dir() and not path.is_symlink():
            for dirEntry in os.scandir(path):
                if recursive:
                    yield from getListOfFiles([Path(dirEntry)], recursive)
                elif dirEntry.is_file():
                    yield Path(dirEntry)
        elif path.is_file():
            yield path








def test():
    # getListOfFiles
    listt = [Path('/home/tuan2le')]
    for entry in getListOfFiles(listt, recursive=True):
        print(entry, "  isfile=",entry.is_file())
