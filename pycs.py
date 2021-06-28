#!/usr/bin/env python3
# Declare  __doc__ attribute:
"""
Usage: checksec_DCV.py [options] <file/directory>...

Options:
    -d --debug
    -h --help
    -o FILE --output=FILE
"""


# http://docopt.org/
from docopt import docopt
import sys
import os
import logging
from datetime import datetime
from src.out import RichOutput

now = datetime.now()
now = now.strftime('%Y-%m-%d %H-%M-%S')

dir_path = os.path.dirname(os.path.realpath(__file__))

def help():
    print(__doc__)


def program(args):
    pass

def setupLogger():
    d_flag = args['--debug']
    llvl = logging.INFO
    if d_flag:
        llvl = logging.DEBUG

    logging.basicConfig(
        # format='[%(asctime)s.%(msecs)03d %(created).04f %(levelname)-8s %(name)-8s %(filename)-16s %(funcName)-16s:%(lineno)-6s PID:%(process)-6s TID:%(thread)-6s]  %(message)s',
        format='[%(asctime)s.%(msecs)03d %(name)-8s %(levelname)-8s %(filename)-16s %(funcName)-16s:%(lineno)-3s]  %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=llvl,
        handlers=[
            logging.FileHandler(
                filename=F'/media/sf_ShareVirtualBox/PyCheckSec/output/123.log',
                mode='w'
                ),
            logging.StreamHandler(sys.stdout)
        ],
    )

if __name__ == "__main__":
    global args
    args = docopt(__doc__)
    setupLogger()
    logging.debug(F'{Cl.Green}abv')
    program(args)

    out = RichOutput()
    # except KeyboardInterrupt:
    #     print('Interrupted')
    #     try:
    #         sys.exit(0)
    #     except SystemExit:
    #         os._exit(0)
