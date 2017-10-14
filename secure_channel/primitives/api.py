"""API classes for primitives library."""

import abc
import enum
import typing


DataBuffer = typing.Union[bytearray, memoryview]


class Direction(enum.Enum):
  """
  Signifies whether we encrypt or decrypt.
  """

  ENCRYPT = 1
  DECRYPT = 2


class HashFunction(object, metaclass=abc.ABCMeta):
  """A hash function."""

  @abc.abstractmethod
  def update(self, data: bytearray) -> None:
    """Updates hmac object with data."""
    raise NotImplementedError

  @abc.abstractmethod
  def finalize(self) -> bytearray:
    """Returns computed hmac."""
    raise NotImplementedError


class HMAC(HashFunction, metaclass=abc.ABCMeta):
  """Initialized hmac function."""

  @abc.abstractmethod
  def verify(self, signature: bytearray):
    """
    Checks current hash input with given signature.
    Uses constant time compare so we don't leak timing info.
    """
    raise NotImplementedError


class CipherMode(object, metaclass=abc.ABCMeta):
  """
  Initialized cipher mode.
  """

  # TODO: Add API to clear state of cipher mode

  @abc.abstractmethod
  def update(self, data: DataBuffer) -> bytearray:
    """
    Encrypt or decrypt the data.
    :param data: Data buffer to encrypt, encryption might be done in place.
    :return: Encrypted or decrypted data. Despite that this might modify
             data buffer
    """

    raise NotImplementedError

  @abc.abstractmethod
  def pad(self, data) -> bytearray:
    """Pads data to block size."""
    raise NotImplementedError

  @abc.abstractmethod
  def unpad(self, data) -> bytearray:
    """Removes padding from data."""
    raise NotImplementedError


class Backend(object):

  """
  Backend instance, that is static and used to create
  hmac and cipher instances.
  """

  @abc.abstractmethod
  def create_hash(self, hash_func: str) -> HashFunction:
    """Create hash function"""
    raise NotImplementedError

  @abc.abstractmethod
  def create_hmac(self, key: bytearray, hash_func: str) -> HMAC:
    """Create initialized instance of hmac."""
    raise NotImplementedError

  @abc.abstractmethod
  def create_cipher_mode(
      self,
      key: bytearray,
      ctr: int,
      cipher: str,
      direction: Direction,
  ) -> CipherMode:
    """Create initialized instance of Cipher Mode."""
    raise NotImplementedError
