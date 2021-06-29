"""
Project :   PyCS
Owner   :   tuan2.le(Le Van Tuan)
Email   :   itadakimatsu97@gmail.com
Descript:   Use Rich.Console framework/ Logging 
"""
from rich.console import Console
import sys
import logging
from logging import StreamHandler, Formatter, FileHandler


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
    formatStr = '[%(asctime)s.%(msecs)0.3d %(name)-4s %(levelname)-6s %(filename)-10s %(funcName)-20s:%(lineno)-3s]  %(message)s'
    def __init__(self) -> None:
        self.__logger = logging.getLogger('dcv')
        self.__config()

    def __config(self) -> None:
        fhandler = FileHandler(filename='log.tmp', mode='w')
        fhandler.setFormatter(Formatter(fmt=self.formatStr))
        self.__logger.addHandler(fhandler)

        self.__logger.setLevel(logging.INFO)

    def addStdout(self)->None:
        shandler = StreamHandler(stream=sys.stdout)
        shandler.setFormatter(Formatter(fmt=self.formatStr))
        self.__logger.addHandler(shandler)

    @property
    def getLLogger(self) -> logging.Logger:
        return self.__logger
