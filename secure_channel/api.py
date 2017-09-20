
import abc
import enum
import threading
import typing


DataBuffer = typing.Union[bytearray, memoryview]


ExtendedKeys = typing.NamedTuple(
  "ExtendedKeys",
  (
    ("send_encryption_key", bytearray),
    ("recv_encryption_key", bytearray),
    ("send_sign_key", bytearray),
    ("recv_sign_key", bytearray),
  )
)


ChannelConfiguration = typing.NamedTuple(
  "ChannelConfiguration",
  (
    # Maximal size of message
    ("max_message_size_bytes", int),
    # Maximal number of messages in session
    ("max_messages_in_session", int),
    ("session_key_length_bytes", int),
  )
)


DEFAULT_CONFIGURATION = ChannelConfiguration(
  # We limit max message size to 256 mb, as messages are stored in memory twice.
  # They need to be stored in memory due to requirement of releasing plaintext
  # out of encryption function only after plaintext is verified.
  # I could store messages on disk, but hey it's a toy project
  max_message_size_bytes=268435456,
  # Full 32 byte counter
  max_messages_in_session=4294967296-1,
  session_key_length_bytes=32
)


class ConfigurationAware(object):

  def __init__(self, configuration: ChannelConfiguration):
    self.__configuration = configuration

  @property
  def configuration(self):
    return self.__configuration


class SessionState(ConfigurationAware):

  def get_send_message_number(self) -> int:
    pass

  def verify_recv_message_number(self, message_number: int):
    pass

  def get_extended_keys(self) -> ExtendedKeys:
    pass

  def reset(self):
    pass


class CommunicationSide(enum.Enum):
  """
  Represents side of communication, to establish secure channel one side **must** set this to ALICE and other to BOB.
  """

  ALICE = 1
  BOB = 2


class Message(object, metaclass=abc.ABCMeta):

  def __init__(self, message_id: int, data: DataBuffer):
    self.message_id = message_id
    self.data = data


class DataSource(object, metaclass=abc.ABCMeta):

  """
  Implements a two-way data source.
  """

  def __init__(self, config: ChannelConfiguration) -> None:
    super().__init__()
    self.__config = config

  @property
  def config(self):
    return self.__config


  @abc.abstractmethod
  def write(self, message: Message):
    """
    Write data to the underlying stream.

    This call is blocking. It will either write whole buffer or raise an exception.
    """
    raise NotImplemented()

  @abc.abstractmethod
  def read(self) -> Message:
    """
    Read data from underlying stream.

    This function has two modes: blocking and non-blocking.

    :return: number of bytes read. This is always a multiple of self.block_size
    """
    raise NotImplemented()


class SessionKeyNegotiator(object,  metaclass=abc.ABCMeta):

  @abc.abstractmethod
  def create_session_key(self, source: DataSource) -> bytearray:
    raise NotImplemented()


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
