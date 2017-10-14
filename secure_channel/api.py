"""API classes."""

import abc
import enum
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


ChannelCryptoConfiguration = typing.NamedTuple(
  "ChannelCryptoConfiguration",
  (
    # Right now protocol version will be identified by single
    # 32 bit int. If you touch anything below bump protocol version.
    ("protocol_version", int),
    ("session_key_length_bytes", int),
    ("block_cipher", str),
    ("hash_algo", str),
  )
)
"""
This is crypto configuration, please don't touch it.
"""

ChannelConfiguration = typing.NamedTuple(
  "ChannelConfiguration",
  (
    # Maximal size of message
    ("max_message_size_bytes", int),
    # Maximal number of messages in session
    ("max_messages_in_session", int),
  )
)
"""
Things in this tuple may be changed by end user, and they
probably won't compromise security.
"""

DEFAULT_CONFIGURATION = ChannelConfiguration(
  # We limit max message size to 256 MB, as messages are stored in memory twice.
  # They need to be stored in memory due to requirement of releasing plaintext
  # out of encryption function only after plaintext is verified.
  # I could store messages on disk, but hey it's a toy project
  max_message_size_bytes=268435456,
  # Full 32 byte counter
  max_messages_in_session=4294967296 - 1,  # TODO: Validate it fits in long
)
"""Feel free to change these."""


class _ConfigurationAware(object):

  """Object aware of configuration and supporting read-only access to it."""
  def __init__(self, configuration: ChannelConfiguration):
    self.__configuration = configuration

  @property
  def configuration(self):
    """Read-only property."""
    return self.__configuration


class SessionState(_ConfigurationAware, metaclass=abc.ABCMeta):

  """Object responsible for maintaining session state, that is:

  1. Generating message numbers for sent messages
  2. Verifying message numbers for received messages.

  """

  @abc.abstractmethod
  def get_send_message_number(self) -> int:
    """
    Get new message id and bump internal state
    to so next call will return greater number.
    """
    raise NotImplementedError

  @abc.abstractmethod
  def verify_recv_message_number(self, message_number: int):
    """

    Raise an error when message number is out of order.

    Current implementations allow gaps in message ids as they
    allow some interesting implementation features.

    .. note::

      Why allow gaps in message ids.

      One possible usage of this (or similar) application would be to
      securely (for once) communicate with remote embedded devices,
      that are not powerful enough to have full HTTPS implementation
      (or a TCP stack even).

      In case of this devices session key negotiation is not an option,
      (but we know that session key will not run out of message_id) ---
      however these devices might not update every sent message id to
      persistent storage could kill their flash memory. So we store
      persistently every, let's say 100 message sent, and on boot up
      increment sent message_id by, let's say, 1000.

    .. note::

      This needs to be called **after**  hmac is verified,
      otherwise attacker might be able to update
      stored message number

    :param message_number:
    :return:
    """
    raise NotImplementedError

  @abc.abstractmethod
  def get_extended_keys(self) -> ExtendedKeys:
    """Return extended keys, you may cache instances of this."""
    raise NotImplementedError

  @abc.abstractmethod
  def reset(self):
    """Destroy state of this instance."""
    raise NotImplementedError


class CommunicationSide(enum.Enum):
  """
  Represents side of communication, to establish secure channel one side
  **must** set this to ALICE and other to BOB.
  """

  ALICE = 1
  BOB = 2


Message = typing.NamedTuple(
  "Message",
  (
    ("message_id", int),
    ("data", DataBuffer),
    ("hmac", DataBuffer),
  ),
)


class DataSource(_ConfigurationAware, metaclass=abc.ABCMeta):

  """
  Implements a two-way data source.
  """

  @abc.abstractmethod
  def write(self, message: Message):
    """
    Write data to the underlying stream.

    This call is blocking. It will either write whole buffer or raise an exception.
    """
    raise NotImplementedError()

  @abc.abstractmethod
  def read(self) -> Message:
    """
    Read data from underlying stream.

    This function has two modes: blocking and non-blocking.

    :return: number of bytes read. This is always a multiple of self.block_size
    """
    raise NotImplementedError()


class SessionKeyNegotiator(object, metaclass=abc.ABCMeta):

  """Negotiates session keys."""

  def create_session_state(
      self,
      data_source: DataSource,
      configuration: ChannelConfiguration
  ) -> SessionState:
    """
    Key negotiator might need to influence Session state to
    generate cryptographically sound system.

    For example negotiator does not negotiate keys, but just
    uses the same session key, storing message serial numbers on disk
    (this makes sense if you *KNOW* your system will send less than
    2^32-1 messages).

    :param data_source: Data source that might be used to
                        negotiate the key.
    :param configuration: Channel configuration.

    """
    raise NotImplementedError


class KeyExtensionFunction(object):

  """
  Object representing secure key extension function.

  It takes a session key and communication side,
  and securely produces for keys for encryption and authentication.

  It is not used explicitly through the API, however most of the
  implementations of SessionState will use such generator
  implicitly.
  """

  @classmethod
  def _swap_keys_for_bob(
      cls,
      side: CommunicationSide,
      extended_keys: ExtendedKeys,
  ) -> ExtendedKeys:
    """
    Helper that swaps send and recv keys if side is bob. You need to call
    it in your implementation of KeyExtensionFunction.

    Feel free to call it from subclasses.
    """
    if side == CommunicationSide.BOB:
      extended_keys = ExtendedKeys(
        send_encryption_key=extended_keys.recv_encryption_key,
        recv_encryption_key=extended_keys.send_encryption_key,
        send_sign_key=extended_keys.recv_sign_key,
        recv_sign_key=extended_keys.send_sign_key,
      )
    return extended_keys

  @abc.abstractmethod
  def extend_keys(
      self,
      side: CommunicationSide,
      session_key: bytes
  ) -> ExtendedKeys:
    """
    Generate extended keys, given session key and communication side.

    Please note that you need to swap keys for bob. There is a
    helper: ``self._swap_keys_for_bob`` that you can use as follows:

    .. code-block::
        extended_keys = ...
        return self._swap_keys_for_bob(extended_keys)
    """
    raise NotImplementedError


class SessionStateLoader(object, metaclass=abc.ABCMeta):

  """
  Thing that loads session state.

  Session state may be persisted between program invocations,
  so this encapsulates this process.

  """

  @abc.abstractmethod
  def create_session_state(
      self,
      configuration: ChannelConfiguration,
      crypto_configuration: ChannelCryptoConfiguration,
  ) -> SessionState:
    """Load session state."""
    raise NotImplementedError
