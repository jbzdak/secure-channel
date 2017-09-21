
import abc
import enum
import typing

DataBuffer = typing.Union[bytearray, memoryview]


class HashFunction(object, metaclass=abc.ABCMeta):

  @property
  @abc.abstractmethod
  def digest_size(self):
    raise NotImplemented

  @abc.abstractmethod
  def update(self, data_buffer):
    raise NotImplemented

  @abc.abstractmethod
  def finalize(self) -> bytearray:
    raise NotImplemented


class BlockCipher(object, metaclass=abc.ABCMeta):

  @property
  def key_size_bytes(self):
    raise NotImplemented

  @property
  def name(self):
    raise NotImplemented

  @property
  def block_size_bytes(self):
    raise NotImplemented


class BlockCipherMode(object, metaclass=abc.ABCMeta):

  def initialize(
      self,
      block_cipher: BlockCipher,
      key: bytearray,
      iv: bytearray
  ):
    raise NotImplemented

  def update(self, databytearray):

