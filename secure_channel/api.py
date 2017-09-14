
import abc
import enum
import typing


DataBuffer = typing.Union[bytes, bytearray, memoryview]


ExtendedKeys = typing.NamedTuple(
  "ExtendedKeys",
  (
    ("send_encryption_key", bytes),
    ("recv_encryption_key", bytes),
    ("send_sign_key", bytes),
    ("recv_sign_key", bytes),
  )
)


class CommunicationSide(enum.Enum):
  """
  Represents side of communication, to establish secure channel one side **must** set this to ALICE and other to BOB.
  """

  ALICE = 1
  BOB = 2


class DataSource(object, metaclass=abc.ABCMeta):

  @abc.abstractmethod
  def write(self, data: DataBuffer):
    raise NotImplemented()

  @abc.abstractmethod
  def read(self, read_into: DataBuffer, blocking: bool= True):
    raise NotImplementedError


class InitialKeyNegotiator(object):

  def __init__(self, source: DataSource, metaclass=abc.ABCMeta):
    self.source = source

  @abc.abstractmethod
  def create_session_key(self) -> bytes:
    raise NotImplementedError


class KeyExtensionFunction(object):

  """
  Object representing secure key extension function.

  It takes a session key and communication side, and securely produces for keys for encryption and authentication.
  """

  @classmethod
  @abc.abstractmethod
  def sign_key_size(cls) -> int:
    """Return size of the generated extended sign key in bytes"""
    return NotImplemented

  @classmethod
  @abc.abstractmethod
  def encrypt_key_size(cls) -> int:
    """Return size of the generated extended encrypt key in bytes"""
    return NotImplemented

  def __init__(self, session_key: bytes, side: CommunicationSide):
    self.session_key = session_key
    self.side = side

  def _swap_keys_for_bob(self, extended_keys: ExtendedKeys) -> ExtendedKeys:
    """
    Helper that swaps send and recv keys if side is bob. You need to call it in your implementation of
    KeyExtensionFunction.

    Feel free to call it from subclasses.
    """
    if self.side == CommunicationSide.BOB:
      extended_keys = ExtendedKeys(
        send_encryption_key=extended_keys.recv_encryption_key,
        recv_encryption_key=extended_keys.send_encryption_key,
        send_sign_key=extended_keys.recv_sign_key,
        recv_sign_key=extended_keys.send_sign_key,
      )
    return extended_keys

  @abc.abstractmethod
  def extend_keys(self) -> ExtendedKeys:
    """
    Generate extended keys, given session key and communication side.

    Please note that you need to swap keys for bob. There is a
    helper: ``self._swap_keys_for_bob`` that you can use as follows:

    .. code-block::
        extended_keys = ...
        return self._swap_keys_for_bob(extended_keys)
    """
    pass
