#!/usr/bin/env python3
from logger import Logger
from rich.console import Console
from time import sleep
from libc import CheckLibC
from elf import ELFSecurity
from pathlib import Path
from utils import getListOfFiles
from elf import ELFChecksecData
import lief
def test_Logger():
    l1= Logger(debug=True)
    l2 = Logger()
    if(l1 == l2):
        print("Singleton!")

    l1.setFileLog()

    for i in range(200):
        l1.log_info("info")
        l1.log_debug("debug")

libc = CheckLibC()
# a = ELFSecurity(Path('/media/sf_KaliShareFolder/PyCS/123'), libc=libc).checksec_state
# a = ELFSecurity(Path(/use/bin/ls'), libc=libc).checksec_state
# ll = getListOfFiles([Path('/usr/bin/atk6-fake_advertise6')], recursive=True)
ll = getListOfFiles([Path('./123')], recursive=True)
for p in ll:
    if lief.is_elf(str(p)):
        print(p)
        st = ELFSecurity((p), libc=libc).checksec_state
        for name, value in zip(st._fields, st):
            print(name , "\t\t", value)