#!/usr/bin/env python3
# Declare  __doc__ attribute i used for parsing options:
"""
Usage: checksec_DCV.py [options] <file/directory>...

Options:
    -d --debug                          Enable log level =Debug
    -c --console                        Enable printing log on console terminal
    -r --recursive                      Enable recursive scaning
    -w WORKERS --workers=WORKERS        Number of worker for multithreading
    -h --help                           Help
    -o FILE --output=FILE               Output file path
"""


# http://docopt.org/
import pathlib
from docopt import docopt
import sys
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import logging
from src.logger import LLogger
import lief
from src.utils import getListOfFiles
from src.elf import ELFSecurity, ELFChecksecData, getLibC
from src.libc import CheckLibC
from src.exceptions import *
import timeit
from datetime import datetime

now = datetime.now()
now = now.strftime('%Y-%m-%d %H-%M-%S')

dir_path = os.path.dirname(os.path.realpath(__file__))

def initializer():
    getLibC()
    pass

def task(p: Path) -> ELFChecksecData:
        logger.debug("Worker %s: checking %s", os.getpid(), p)
        res = ELFSecurity(p)
        return res.checksec_state

def program(args: dict) -> None:
    pathList = [Path(entry) for entry in args['<file/directory>']]
    workers = int(args['--workers']) if args['--workers'] else os.cpu_count()
    recursive = args['--recursive']

    logger.info('Input: %d paths to dir/file.', len(pathList))
    logger.info('Input: %d workers.', workers)
    logger.info('Input: recursive mode = %s', 'True' if recursive else 'False')

    # Scan libc
    # libc = None
    # try:
    #     libc = CheckLibC()
    #     logger.info('LibC: %d fortified symbols', len(libc.listOfFortified))
    #     logger.info('LibC: %d fortifable symbols', len(libc.listOfFortifable))
    #     logger.info('Get LibC successfully!')
    # except LibCNotFound as err:
    #     logger.info('Error: %s', err)
    # except ParsingFailed as err:
    #     logger.info('Error: %s', err)


    start = timeit.default_timer()
    # Scan all files in pathList
    try:
        count = sum(1 for i in getListOfFiles(pathList, recursive))
        logger.info('Get list of files: %d files', count)
    except:
        # listOfFiles = None
        logger.info('Get list of files failed')

    # Thread pool
    # try:
    with ProcessPoolExecutor(max_workers=workers, initializer=getLibC) as pool:
        futures_in_pool = {
            pool.submit(
                task, entry
            ): entry for entry in getListOfFiles(pathList, recursive) if lief.is_elf(str(entry))
        }
        for future in as_completed(futures_in_pool):
            p = futures_in_pool[future]
            logger.debug(F'{p}:{future.result()}')
            # logger.info(F'{p} : {res.checksec_state}')
            # res = future.result()
            # try:
            #     res = future.result()
            # except:
            #     logger.info("error")
            # else:
            #     logger.info(F'{p} : {res.checksec_state}')
    # manual:
    # for entry in getListOfFiles(pathList, recursive):
    #     if lief.is_elf(str(entry)):
    #         ress = task(entry)
    #         logger.debug(F'{entry}:{ress}')

    stop = timeit.default_timer()

    logger.info(F'RunTime= {stop-start}')
    # except:
    #     pass


if __name__ == "__main__":
    args = docopt(__doc__)

    # Setup logger agent:
    debug = args['--debug']
    console = args['--console']
    logger = LLogger().getLLogger
    if debug:
        logger.setLevel(logging.DEBUG)

    if console:
        LLogger().addStdout()

    # try:
    #     logger.info('------------START------------')
    program(args)
    # except KeyboardInterrupt:
    #     logger.info('Interrupted')
    # finally:
    #     logger.info('------------END-------------')
    #     try:
    #         sys.exit(0)
    #     except SystemExit:
    #         os._exit(0)
