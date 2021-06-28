from abc import ABC
import logging
from collections import namedtuple
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, List, Optional, TYPE_CHECKING, Union


import lief

from libc import CheckLibC
from exceptions import ParsingFailed

if TYPE_CHECKING:
    from elf import ELFChecksecData

ELFChecksecData = namedtuple(
    "ELFChecksecData",
    [
        "relro",
        "canary",
        "nx",
        "pie",
        "rpath",
        "runpath",
        "symbols",
        "fortify_source",
        "fortified",
        "fortifiable",
        "fortify_score",
    ],
)


class RelroType(Enum):
    No = 1
    Partial = 2
    Full = 3


class PIEType(Enum):
    No = 1
    DSO = 2
    PIE = 3


class BinarySecurity(ABC):
    def __init__(self, bin_path: Path):
        self.bin = lief.parse(str(bin_path))
        if not self.bin:
            raise ParsingFailed(bin_path)

    @property
    def has_nx(self) -> bool:
        return self.bin.has_nx

    @property
    def checksec_state(self) -> ELFChecksecData:
        raise NotImplementedError


class ELFSecurity(BinarySecurity):
    def __init__(self, elf_path: Path, libc: CheckLibC = None):
        super().__init__(elf_path)
        self._libc = False
        if not libc:
            self._libc = True
            self.cmpFortified = libc.listOfFortified
            self.cmpFortifable = libc.listOfFortifable

    @property
    @lru_cache()
    def set_dyn_syms(self) -> FrozenSet[str]:
        return frozenset(f.name for f in self.bin.dynamic_symbols)

    @property
    def relro(self) -> RelroType:
        # tuan2.ledd: fix bug Partial Relro
        try:
            self.bin.get(lief.ELF.SEGMENT_TYPES.GNU_RELRO)

        except lief.not_found:
            return RelroType.No

        try:
            if lief.ELF.DYNAMIC_FLAGS.BIND_NOW in self.bin.get(lief.ELF.DYNAMIC_TAGS.FLAGS):
                return RelroType.Full
            else:
                return RelroType.Partial

        except lief.not_found:
            return RelroType.Partial


    @property
    def has_canary(self) -> bool:
        canary_sections = ["__stack_chk_fail", "__intel_security_cookie"]
        for section in canary_sections:
            try:
                if self.bin.get_symbol(section):
                    return True
            except lief.not_found:
                pass
        return False

    @property
    def pie(self) -> PIEType:
        if self.bin.is_pie:
            if self.bin.has(lief.ELF.DYNAMIC_TAGS.DEBUG):
                return PIEType.PIE
            else:
                return PIEType.DSO
        return PIEType.No

    @property
    def has_rpath(self) -> bool:
        try:
            if self.bin.get(lief.ELF.DYNAMIC_TAGS.RPATH):
                return True
        except lief.not_found:
            pass
        return False

    @property
    def has_runpath(self) -> bool:
        try:
            if self.bin.get(lief.ELF.DYNAMIC_TAGS.RUNPATH):
                return True
        except lief.not_found:
            pass
        return False

    @property
    @lru_cache()
    def symbols(self) -> List[str]:
        return [symbol.name for symbol in self.bin.static_symbols]

    @property
    def is_stripped(self) -> bool:
        # TODO: hwo to reset static_symbols iterator for the next call to symbols() ?
        # consumes only the first symbol from iterator, saving CPU cycles
        try:
            next(self.bin.static_symbols)
        except StopIteration:
            return True
        else:
            return False

    @property
    def is_fortified(self) -> bool:
        return True if self.fortified else False

    @property
    @lru_cache()
    def fortified(self) -> Optional[FrozenSet[str]]:
        """Get the list of fortified symbols"""
        if not self._libc:
            return None
        return self.set_dyn_syms & self.cmpFortified

    @property
    @lru_cache()
    def fortifiable(self) -> Optional[FrozenSet[str]]:
        """Get the list of fortifiable symbols (fortified + unfortified)"""
        if not self._libc:
            return None
        return self.set_dyn_syms & self.cmpFortifable

    @property
    def checksec_state(self) -> ELFChecksecData:
        fortify_source = None
        fortified_count = None
        fortifiable_count = None
        score = None
        if self._libc:
            fortified_count = len(self.fortified)
            fortifiable_count = len(self.fortifiable)
            if not self.is_fortified:
                score = 0
            else:
                # fortified
                if fortified_count == 0:
                    # all fortified !
                    score = 100
                else:
                    score = (fortified_count * 100) / fortifiable_count
                    score = round(score)

            fortify_source = True if fortified_count != 0 else False
        return ELFChecksecData(
            relro=self.relro,
            canary=self.has_canary,
            nx=self.has_nx,
            pie=self.pie,
            rpath=self.has_rpath,
            runpath=self.has_runpath,
            symbols=not self.is_stripped,
            fortify_source=fortify_source,
            fortified=fortified_count,
            fortifiable=fortifiable_count,
            fortify_score=score,
        )
