"""
Project :   PyCS
Owner   :   tuan2.le(Le Van Tuan)
Email   :   itadakimatsu97@gmail.com
Descript:   Use Rich.Console framework/ Logging 
"""
from enum import Enum
from threading import local
from typing import Any
from rich.console import Console
import sys
import logging
from logging import StreamHandler, Formatter, FileHandler
from rich.logging import RichHandler


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(
                Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class RichLogger(metaclass=Singleton):
    def __init__(self, debug: bool = False) -> None:
        self._agent_file = Console()
        self._agent = Console()
        self._file = False
        self._debug = debug

    def __del__(self):
        if self._file:
            self._agent_file.file.close()

    def setFileLog(self) -> None:
        self._file = True
        self._agent_file.file = open('./log.tmp', 'w')

    def isSetFileLOg(self) -> bool:
        return self._file

    def log_debug(self, content) -> None:
        if not self._debug:
            return
        if self._file:
            self._agent_file.log('[DEBUG]', content, log_locals=True)
        self._agent.log('[DEBUG]', content, log_locals=True)

    def log_info(self, content) -> None:
        if self._file:
            self._agent_file.log('[INFO]', content)
        self._agent.log('[INFO]', content)


class LLogger(metaclass=Singleton):
    formatStr = '[%(asctime)s] %(name)-4s %(levelname)-6s %(filename)-20s:%(lineno)-4s %(processName)-15s] %(message)s'

    def __init__(self) -> None:
        self.__logger = logging.getLogger('dcv')

        #This will prevent logging from being send to the upper logger
        #that includes the console logging.
        self.__logger.propagate = False
        self.__config()

    def __config(self) -> None:
        fhandler = FileHandler(filename='log.tmp', mode='w')
        fhandler.setFormatter(Formatter(fmt=self.formatStr))
        fhandler.setLevel(logging.DEBUG)
        self.__logger.addHandler(fhandler)
        self.__logger.setLevel(logging.DEBUG)

    def addRichHandler(self, level: Any = logging.INFO) -> None:
        richHandler = RichHandler(
            markup=False,
            omit_repeated_times=False,
            log_time_format="%Y-%m-%d %H:%M:%S.%f",
            rich_tracebacks=True,
        )
        richHandler.setLevel(level)
        self.__logger.addHandler(richHandler)

    @property
    def getLLogger(self) -> logging.Logger:
        return self.__logger
