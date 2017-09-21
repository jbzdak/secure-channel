


import abc
import enum
import typing

DataBuffer = typing.Union[bytearray, memoryview]

class Direction(enum.Enum):

  ENCRYPT = 1
  DECRYPT = 2


class HMAC(object, metaclass=abc.ABCMeta):

  @abc.abstractmethod
  def update(self, data: bytearray):
    raise NotImplemented

  @abc.abstractmethod
  def finalize(self) -> bytearray:
    raise NotImplemented

  @abc.abstractmethod
  def verify(self, signature: bytearray):
    raise NotImplemented


class CipherMode(object, metaclass=abc.ABCMeta):
  """This one works in-place."""

  @abc.abstractmethod
  def update(self, data: DataBuffer) -> bytearray:
    raise NotImplemented


class Backend(object):

  @abc.abstractmethod
  def create_hmac(self, key: bytearray, hash: str) -> HMAC:
    raise NotImplemented

  @abc.abstractmethod
  def create_cipher_mode(
      self,
      key: bytearray,
      iv: bytearray,
      cipher: bytearray,
  ):
    raise NotImplemented
