from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table, box
from typing import Any, Callable
from pathlib import Path
from .IDataCollector import IDataCollector
from src.elf import ELFChecksecData, PIEType, RelroType
import logging


class RichTable(IDataCollector):
    def __init__(self, richConsole: Console = None, is_libc_exists: bool = False):
        super().__init__()
        self.logger = logging.getLogger('dcv')
        self._libc = is_libc_exists

        # rich console
        if richConsole:
            self.console = richConsole
        else:
            self.console = Console()

        #initialize Table and Progress bar
        self.initTable()
        self.initBarProgress()

    def __enter__(self):
        self.logger.debug('Enter RichTable object.')
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        # self.logger.debug('Exit RichTable: exception_type=', exception_type)
        # self.logger.debug('Exit RichTable: exception_value=', exception_value)
        # self.logger.debug('Exit RichTable: exception_traceback=', exception_traceback)
        # cleanup the Rich progress bars
        if self.checkingProgress is not None:
            self.checkingProgress.stop()
        if self.printingProgress is not None:
            self.printingProgress.stop()
        if self.enumerateProgress is not None:
            self.enumerateProgress.stop()
        return

    def initTable(self) -> None:
        self.table = Table(
            title="Table: ELF Checsec results",
            box=box.DOUBLE_EDGE,
            show_lines=True,
            expand=True
        )
        self.table.add_column("[bold s red]No.", justify="left")
        self.table.add_column("File", justify="left", header_style="")
        self.table.add_column("NX", justify="center")
        self.table.add_column("PIE", justify="center")
        self.table.add_column("Canary", justify="center")
        self.table.add_column("Relro", justify="center")
        self.table.add_column("RPATH", justify="center")
        self.table.add_column("RUNPATH", justify="center")
        self.table.add_column("Symbols", justify="center")
        if self._libc:
            self.table.add_column("FORTIFY", justify="center")
            self.table.add_column("Fortified", justify="center")
            self.table.add_column("Fortifiable", justify="center")
            self.table.add_column("Fortify Score", justify="center")

    def initBarProgress(self) -> None:
        self.checkingProgress = Progress(
            TextColumn("[bold blue]Processing...", justify="left"),
            BarColumn(bar_width=None),
            "{task.completed}/{task.total}",
            "•",
            "[progress.percentage]{task.percentage:>3.1f}%",
            console=self.console,
        )
        self.printingProgress = Progress(
            BarColumn(bar_width=None),
            TextColumn("[bold blue]{task.description}", justify="center"),
            BarColumn(bar_width=None),
            console=self.console,
            transient=True,
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
            F'[bold red]Displaying Result: {self.table.row_count} records', characters='.')
        with self.printingProgress:
            taskID = self.printingProgress.add_task(
                'Showing Table:...', start=False)
            self.console.print(self.table)
            self.printingProgress.remove_task(taskID)

        self.console.rule('[bold red]Displaying Done', characters='.',)
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
            row_res: List[str] = []
            # NX
            if not checksec.nx:
                nx_res = "[red]No"
            else:
                nx_res = "[green]Yes"
            row_res.append(nx_res)
            # PIE
            pie = checksec.pie
            if pie == PIEType.No:
                pie_res = f"[red]{pie.name}"
            elif pie == PIEType.DSO:
                pie_res = f"[yellow]{pie.name}"
            else:
                pie_res = "[green]Yes"
            row_res.append(pie_res)
            # CANARY
            if not checksec.canary:
                canary_res = "[red]No"
            else:
                canary_res = "[green]Yes"
            row_res.append(canary_res)
            # RELRO
            relro = checksec.relro
            if relro == RelroType.No:
                relro_res = f"[red]{relro.name}"
            elif relro == RelroType.Partial:
                relro_res = f"[yellow]{relro.name}"
            else:
                relro_res = f"[green]{relro.name}"
            row_res.append(relro_res)
            # RPATH
            if checksec.rpath:
                rpath_res = "[red]Yes"
            else:
                rpath_res = "[green]No"
            row_res.append(rpath_res)
            # RUNPATH
            if checksec.runpath:
                runpath_res = "[red]Yes"
            else:
                runpath_res = "[green]No"
            row_res.append(runpath_res)
            # SYMBOLS
            if checksec.symbols:
                symbols_res = "[red]Yes"
            else:
                symbols_res = "[green]No"
            row_res.append(symbols_res)

            # fortify results depend on having a Libc available
            if self._libc:
                fortified_count = checksec.fortified
                if checksec.fortify_source:
                    fortify_source_res = "[green]Yes"
                else:
                    fortify_source_res = "[red]No"
                row_res.append(fortify_source_res)

                if fortified_count == 0:
                    fortified_res = "[red]No"
                else:
                    fortified_res = f"[green]{fortified_count}"
                row_res.append(fortified_res)

                fortifiable_count = checksec.fortifiable
                if fortified_count == 0:
                    fortifiable_res = "[red]No"
                else:
                    fortifiable_res = f"[green]{fortifiable_count}"
                row_res.append(fortifiable_res)

                if checksec.fortify_score == 0:
                    fortified_score_res = f"[red]{checksec.fortify_score}"
                elif checksec.fortify_score == 100:
                    fortified_score_res = f"[green]{checksec.fortify_score}"
                else:
                    fortified_score_res = f"[yellow]{checksec.fortify_score}"
                row_res.append(fortified_score_res)

            self.table.add_row(str(self.table.row_count+1),
                               str(filepath), *row_res)
        else:
            raise NotImplementedError

    def postAppending(self):
        self.checkingProgress.update(self.checkingProgress_ID, advance=1)

    def enumerateTask(self, total: int, func: Callable[..., int], *args) -> None:
        return super().enumerateTask(total=total, func=func, *args)
