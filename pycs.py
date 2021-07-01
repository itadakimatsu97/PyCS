#!/usr/bin/env python3
# Declare  __doc__ attribute i used for parsing options:
"""
Usage: checksec_DCV.py [options] [console] <file/directory>...

Options:
    -r --recursive                      Enable recursive scaning, default is not-recursive
    -w WORKERS --workers=WORKERS        Number of worker for multithreading, default = 2*numOfProcessor
    -o FILE --output=FILE               Output file path
    -h --help                           Help

# Program always export full log into ./log.tmp
Console:
    -c --console                        Enable printing log on console terminal, default level =INFO
    -d --debug                          Set console log level =DEBUG
"""


# http://docopt.org/
from docopt import docopt
import sys
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import rich
from src.logger import LLogger
import lief
from src.utils import getListOfFiles
from src.elf import ELFSecurity, ELFChecksecData, getLibC
from src.exceptions import *
from src.dataCollectors.RichTable import *
from rich.console import Console
import timeit


def initializer():
    getLibC()
    pass


def task(p: Path) -> ELFChecksecData:
    logging.getLogger('dcv').debug(F"Checking: {p}")
    res = ELFSecurity(p)
    return res.checksec_state


def program(args: dict) -> None:
    richConsole = Console()
    richConsole.rule(characters='.')
    richConsole.rule('[bold red]Program start!', characters='.')
    richConsole.rule('[bold red]Setting up', characters='.')
    start = timeit.default_timer()

    pathList = [Path(entry) for entry in args['<file/directory>']]
    workers = int(args['--workers']) if args['--workers'] else os.cpu_count()
    recursive = args['--recursive']

    logger.info('Input: %d paths to dir/file.', len(pathList))
    logger.info('Input: %d workers.', workers)
    logger.info('Input: recursive mode = %s', 'True' if recursive else 'False')
    lief.logging.disable()

    libc_detected = False
    libc = getLibC()
    if libc:
        libc_detected = True
    else:
        logger.debug("Could not locate libc. Skipping fortify tests for ELF.")

    # Thread pool
    output_cls = RichTable
    with output_cls(is_libc_exists=libc_detected) as check_output:
        try:
            try:
                count = sum(1 for i in getListOfFiles(
                    pathList, recursive) if lief.is_elf(str(i)))
            except KeyboardInterrupt:
                logger.info('Enumerating is stopped by keyboard interrupt.')
            else:
                check_output.enumerateTask(total=count, func=None)

            with ProcessPoolExecutor(max_workers=workers, initializer=getLibC) as pool:
                try:
                    check_output.startJob()

                    futures_in_pool = {
                        pool.submit(
                            task, entry
                        ): entry for entry in getListOfFiles(pathList, recursive) if lief.is_elf(str(entry))
                    }
                    global cnt
                    cnt = 1
                    for future in as_completed(futures_in_pool):
                        filepath = futures_in_pool[future]
                        try:
                            data = future.result()
                        except:
                            logger.debug(F'Future error: {filepath}')
                        else:
                            check_output.appendingNewRecord(filepath, data)
                        finally:
                            check_output.postAppending()
                            logger.debug(
                                F"Checked[{cnt:-8}/{count}] {filepath}")
                            cnt += 1
                            pass
                except KeyboardInterrupt:
                    logger.info('Checking is stopped by keyboard interrupt.')
                    check_output.__exit__(None, None, None)
                    logging.info("Shutdown Process Pool ...")
                    pool.shutdown(wait=True)

        except KeyboardInterrupt:
            pass
        else:
            check_output.finishJob()

    duration = timeit.default_timer() - start
    richConsole.rule(
        F'[bold red]Program end! RunTime= {duration.__round__(4)} (seconds)', characters='.')


if __name__ == "__main__":
    args = docopt(__doc__)

    debug = args['--debug']
    console = args['--console']
    logger = LLogger().getLLogger
    if console:
        if debug:
            LLogger().addRichHandler(logging.DEBUG)
        else:
            LLogger().addRichHandler()

    try:
        program(args)
    except KeyboardInterrupt:
        logger.info('Stop by keyboard interrupt.')
    finally:
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
