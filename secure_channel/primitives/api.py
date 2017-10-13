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


class HMAC(object, metaclass=abc.ABCMeta):
  """Initialized hmac function."""

  @abc.abstractmethod
  def update(self, data: bytearray) -> None:
    """Updates hmac object with data."""
    raise NotImplementedError

  @abc.abstractmethod
  def finalize(self) -> bytearray:
    """Returns computed hmac."""
    raise NotImplementedError

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

  # TODO: Add api to clear state of cipher mode

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
    raise NotImplementedError

  @abc.abstractmethod
  def unpad(self, data) -> bytearray:
    raise NotImplementedError


class Backend(object):

  @abc.abstractmethod
  def create_hmac(self, key: bytearray, hash: str) -> HMAC:
    raise NotImplementedError

  @abc.abstractmethod
  def create_cipher_mode(
      self,
      key: bytearray,
      ctr: int,
      cipher: str,
      direction: Direction,
  ):
    raise NotImplementedError
