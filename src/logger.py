"""
Project :   PyChecksec
Owner   :   tuan2.le(Le Van Tuan)
Email   :   itadakimatsu97@gmail.com
"""
from rich.console import Console
import sys


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(
                Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Logger(metaclass=Singleton):
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
        self._agent_file.file = open('./log_tmp', 'w')

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
