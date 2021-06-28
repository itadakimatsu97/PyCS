#!/usr/bin/env python3
from logger import Logger
from rich.console import Console
from time import sleep

def test_Logger():
    l1= Logger(debug=True)
    l2 = Logger()
    if(l1 == l2):
        print("Singleton!")

    # l1.setFileLog()

    for i in range(200):
        l1.log_info("info")
        l1.log_debug("debug")


test_Logger()