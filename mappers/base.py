from abc import ABC, abstractmethod

from flask import Response


class BaseMapper(ABC):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    @abstractmethod
    def auth(self, response: Response, scope: str = '') -> Response:
        """ Map auth data """
        raise NotImplementedError

    @abstractmethod
    def info(self, scope: str = ''):
        """ Map info data """
        raise NotImplementedError

