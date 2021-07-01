import typing
from typing import NamedTuple, Any, Callable
from pathlib import Path
from abc import ABC, abstractmethod


class IDataCollector(ABC):
    """
    Abstraction Class for making data collector:
    - Rich Table
    - Json
    - CSV
    - XML
    """

    def __init__(self):
        self.totalDataRecored = None

    @abstractmethod
    def __enter__(self):
        """
        Using pair of magic methods (__enter__, __exit__) allows you to implement objects \n
        which can be used easily with the with statement.
        Refer: https://docs.python.org/3/reference/datamodel.html#object.__enter__ \n
        Returns:
            self: this
        """
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        """
        Using pair of magic methods (__enter__, __exit__) allows you to implement objects \n
        which can be used easily with the with statement.
        Refer: https://docs.python.org/3/reference/datamodel.html#object.__exit__ \n
        Returns: Void
        """
        return

    def enumerateTask(self, total: int = None, func: Callable[..., int] = None, *args) -> None:
        """
        Provide <total> or <func> notify that how many record need to be collected.

        Args:
            total (int, optional): [description]. Defaults to None.
            func (Function, optional): [description]. Defaults to None.
        """
        if total:
            self.totalDataRecored = total
        else:
            self.totalDataRecored = func(*args)

    @abstractmethod
    def appendingNewRecord(self, filepath: Path, record: Any):
        """Add a checksec file result to the output"""
        raise NotImplementedError

    @abstractmethod
    def postAppending(self):
        """This method is trigger for every file processed, even if the processing failed."""
        raise NotImplementedError

    @abstractmethod
    def startJob(self) -> None:
        """Job processing has started"""
        raise NotImplementedError

    @abstractmethod
    def finishJob(self) -> None:
        """Finishing the Job"""
        raise NotImplementedError
