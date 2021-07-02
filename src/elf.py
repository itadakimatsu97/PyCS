"""
Project     : PyCS
Owner       : tuan2.le(Le Van Tuan)
Email       : itadakimatsu97@gmail.com
Description : Reworks base on Checksec.py and fix its bug-cannot check parital relro
"""

from abc import ABC
from collections import namedtuple
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, List, Optional
import lief
import subprocess

from .libc import CheckLibC
from .exceptions import ParsingFailed

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

__LIBC = {}


def getLibC():
    global __LIBC
    try:
        __LIBC['libc']
    except KeyError:
        try:
            libc = CheckLibC()
        except:
            __LIBC["libc"] = None
        else:
            __LIBC["libc"] = libc
    return __LIBC["libc"]


class RelroType(Enum):
    No = 1,
    Partial = 2
    Full = 3


class PIEType(Enum):
    No = 1
    DSO = 2
    PIE = 3


class BinarySecurity(ABC):
    def __init__(self, bin_path: Path):
        self.path = bin_path
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
    def __init__(self, elf_path: Path):
        super().__init__(elf_path)
        libc = getLibC()
        if libc:
            self._libc = True
            self.cmpFortified = libc.listOfFortified
            self.cmpFortifable = libc.listOfFortifable
        else:
            self._libc = False

    @property
    @lru_cache()
    def set_dyn_syms(self) -> FrozenSet[str]:
        return frozenset(f.name for f in self.bin.dynamic_symbols)

    # tuan2.le: fix bug Partial Relro
    @property
    def relro(self) -> RelroType:
        try:
            self.bin.get(lief.ELF.SEGMENT_TYPES.GNU_RELRO)
        except lief.not_found:
            return RelroType.No

        # print(self.bin.get(lief.ELF.DYNAMIC_TAGS.FLAGS))
        try:
            self.bin.has(lief.ELF.DYNAMIC_TAGS.FLAGS.BIND_NOW)
            return RelroType.Full
        except lief.not_found:
            return RelroType.Partial

    # Tuan2.le:
    @property
    def has_canary(self) -> bool:
        # Using lief
        canary_sections = ["__stack_chk_fail", "__intel_security_cookie"]
        for section in canary_sections:
            try:
                if self.bin.get_symbol(section):
                    return True
            except lief.not_found:
                pass

        # Using strings
        command = F"strings {self.path} | grep -E '__stack_chk_fail|__intel_security_cookie'"
        output, error = subprocess.Popen(
            command, shell=True, executable="/bin/bash", stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        if output:
            return True

        # Using xxd to check hex
        canary_hex = ["64488b042528000000", "65a114000000"]
        command = F"xxd -p {self.path}"
        output, error = subprocess.Popen(
            command, shell=True, executable="/bin/bash", stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        output = output.decode('utf-8').strip()
        for hexx in canary_hex:
            if hexx in output:
                return True
        return False

    # tuan2.leFix check PIE
    @property
    def pie(self) -> PIEType:
        if self.bin.header.file_type == lief.ELF.E_TYPE.DYNAMIC:
            if self.bin.is_pie:
                if self.bin.has(lief.ELF.DYNAMIC_TAGS.DEBUG):
                    return PIEType.PIE
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
