import csv
from typing import Callable
from pathlib import Path
from .IDataCollector import IDataCollector
from src.elf import ELFChecksecData, PIEType, RelroType
from rich.progress import Progress, BarColumn, TextColumn
import logging


class CsvCollector(IDataCollector):
    def __init__(self, filePath: Path, is_libc_exists: bool = False):
        super().__init__()
        self.logger = logging.getLogger('dcv')
        self._libc = is_libc_exists
        self.filePath = filePath
        self.file = None
        self.csv = None

    def __enter__(self):
        self.logger.debug('Enter CSVCollector object.')
        self.file = open(self.filePath, newline='', mode='w')
        fieldnames = ['RELRO', 'STACK CANARY', 'NX', 'PIE',
                      'RPATH', 'RUNPATH', 'FORTIFY-SOURCE', 'FILE']

        self.csv = csv.DictWriter(self.file, fieldnames=fieldnames)
        self.csv.writeheader()
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        if self.file is not None:
            self.file.close()

        return

    def initBarProgress(self) -> None:
        self.checkingProgress = Progress(
            TextColumn("[bold blue]Processing...", justify="left"),
            BarColumn(bar_width=None),
            "{task.completed}/{task.total}",
            "•",
            "[progress.percentage]{task.percentage:>3.1f}%",
            console=self.console,
        )
        self.enumerateProgress = Progress(
            TextColumn("[bold blue]Enumerating...", justify="center"),
            BarColumn(bar_width=None),
            console=self.console,
            transient=True,
        )

    def startJob(self) -> None:
        self.checkingProgress.start()
        self.checkingProgress_ID = self.checkingProgress.add_task(
            description='Checking',
            total=self.totalDataRecored,
            start=True,
        )

    def finishJob(self) -> None:
        self.checkingProgress.stop()

        if not self.table.row_count > 0:
            self.console.rule('Displaying Result: No records', characters='.')
            return

        self.console.rule(
            F'[bold red]Writing Result: {self.table.row_count} records', characters='.')
        self.console.rule('[bold red]Writing Done', characters='.',)
        self.console.rule(characters='.')

    def appendingNewRecord(self, filepath: Path, record: Any):
        checksec = record
        d = checksec._asdict()
        message = ""
        for key, val in d.items():
            message += F"|{key.upper():<20}:{str(val):<20}|\n"
        self.logger.debug(
            F"Result for {filepath}: \n{message}"
        )
        if isinstance(checksec, ELFChecksecData):
            row = {
                'FILE': str(filepath)
            }
            # NX
            if not checksec.nx:
                row['NX'] = "NX disabled"
            else:
                row['NX'] = "NX enabled"
            # PIE
            pie = checksec.pie
            if pie == PIEType.No:
                row['PIE'] = "No PIE"
            elif pie == PIEType.DSO:
                row['PIE'] = "DSO"
            else:
                row['PIE'] = "PIE enabled"
            # CANARY
            if not checksec.canary:
                row['STACK CANARY'] = "No canary found"
            else:
                row['STACK CANARY'] = "Canary found"
            # RELRO
            relro = checksec.relro
            if relro == RelroType.No:
                row['RELRO'] = "No RELRO"
            elif relro == RelroType.Partial:
                row['RELRO'] = "Partial RELRO"
            else:
                row['RELRO'] = "Full RELRO"
            # RPATH
            if checksec.rpath:
                row['RPATH'] = "RPATH"
            else:
                row['RPATH'] = "No RPATH"
            # RUNPATH
            if checksec.runpath:
                row['RUNPATH'] = "RUNPATH"
            else:
                row['RUNPATH'] = "No RUNPATH "
            # SYMBOLS
            if checksec.symbols:
                symbols_res = "[red]Yes"
            else:
                symbols_res = "[green]No"
            row.append(symbols_res)

            # fortify results depend on having a Libc available
            if self._libc:
                fortified_count = checksec.fortified
                if checksec.fortify_source:
                    row['FORTIFY-SOURCE'] = "Enabled"
                else:
                    row['FORTIFY-SOURCE'] = "Disabled"
            else:
                row['FORTIFY-SOURCE'] = ""

            self.csv.writerow(row)
        else:
            raise NotImplementedError

    def postAppending(self):
        self.checkingProgress.update(self.checkingProgress_ID, advance=1)

    def enumerateTask(self, total: int, func: Callable[..., int], *args) -> None:
        return super().enumerateTask(total=total, func=func, *args)
