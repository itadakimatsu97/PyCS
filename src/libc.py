from pathlib import Path
from typing import FrozenSet, Tuple
from functools import lru_cache
from exceptions import LibCNotFound, ParsingFailed
import lief
import os


class CheckLibC():
    PATH_POSSIBLE = [
        "/lib/libc.so.6",
        "/lib/libc.so.7",
        "/lib/libc.so",
        "/lib64/libc.so.6",
        "/lib/i386-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/arm-linux-gnueabihf/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/usr/x86_64-gentoo-linux-musl/bin/ld",
    ]
    STAR_MARKER = '__'
    END_MARKER = '_chk'

    def __init__(self) -> None:
        self.libCPath = self.findLibC()
        if not self.libCPath:
            raise LibCNotFound()
        self.libCParse = lief.parse(str(self.libCPath))
        if not self.libCParse:
            raise ParsingFailed(self.libCPath)

        self.listOfFortified = self.getFortifiedSymbols()
        self.listOfFortifable = self.getFortifiedSymbols() | self.getFortifableSymbols()

    def findLibC(cls) -> Path:
        """d
        For checking Fortify source
        """
        target = None
        for p in cls.PATH_POSSIBLE:
            posixPath = Path(p)
            if posixPath.exists():
                if posixPath.is_symlink():
                    target = Path(os.readlink(posixPath))
                    # break
                if lief.is_elf(str(posixPath)):
                    target = posixPath
        return target

    @lru_cache
    def getFortifiedSymbols(self) -> FrozenSet:
        """
        '__stpcpy_chk'
        """
        return frozenset({func.name for func in self.libCParse.symbols if func.name.endswith(self.END_MARKER)})

    @lru_cache
    def getFortifableSymbols(self) -> FrozenSet:
        """
        'stpcpy'
        """
        return frozenset({strr[len(self.STAR_MARKER):-len(self.END_MARKER)] for strr in self.getFortifiedSymbols()})
