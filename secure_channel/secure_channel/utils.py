"""
Utility classes for SecureChannel.

These utility classes are used to hide implementation details of SecureChannel
from end-user. Basically SecureChannel has now two functions: send_message
and receive_message.

"""

# pylint: disable=protected-access

import pickle
import typing

from secure_channel import api
from secure_channel.primitives import BACKEND, HMAC, Direction
from secure_channel.primitives.utils import format_counter

if typing.TYPE_CHECKING:
  from .proper import SecureChannel  # pylint: disable=unused-import


CRYPTO_CONFIGURATION = api.ChannelCryptoConfiguration(
  protocol_version=1,
  session_key_length_bytes=16,
  block_cipher="AES",
  hash_algo="SHA-256"
)


class CryptoDetailsSerializedForm(object):
  """
  Utility class used to serialize named tuple along with field
  names and types.
  """

  def __init__(self, crypto_configuration: api.ChannelCryptoConfiguration):
    self.field_names = crypto_configuration._fields
    self.field_types = crypto_configuration._field_types
    self.data = tuple(crypto_configuration)


class SecureChannelUtils(object):
  """
  Base class for helpers.
  """

  def __init__(self, channel: "SecureChannel"):
    self.channel = channel

  def _update_hmac_with_crypto_details(self, hmac: HMAC):
    serialized_details = pickle.dumps(CryptoDetailsSerializedForm(self.channel.crypto_config))
    hmac.update(format_counter(len(serialized_details)))
    hmac.update(serialized_details)

  def _get_data_hmac(self, message_id, data, key) -> HMAC:
    hmac = BACKEND.create_hmac(key, self.channel.crypto_config.hash_algo)
    hmac.update(format_counter(message_id))
    self._update_hmac_with_crypto_details(hmac)
    hmac.update(format_counter(len(data)))
    hmac.update(data)
    return hmac


class SendMessageUtils(SecureChannelUtils):
  """
  Helper to send the message.
  """

  def send_message(self, data: api.DataBuffer):
    """Sends the message synchronously."""
    message_id = self.channel._session_state.get_send_message_number()
    hmac = self._get_sent_message_hmac(message_id, data)
    message = self._encrypt_message(message_id, data, hmac)
    self.channel._data_source.write(message)

  def _get_sent_message_hmac(
      self,
      message_id: int,
      data: api.DataBuffer
  ) -> bytearray:
    key = self.channel.extended_keys.send_sign_key
    hmac = self._get_data_hmac(message_id, data, key)
    return hmac.finalize()

  def _encrypt_message(self, message_id, data, hmac):
    cipher = BACKEND.create_cipher_mode(
      key=self.channel.extended_keys.send_encryption_key,
      ctr=message_id,
      cipher=self.channel.crypto_config.block_cipher,
      direction=Direction.ENCRYPT
    )

    return api.Message(
      message_id=message_id,
      data=cipher.update(data),
      hmac=cipher.update(cipher.pad(hmac))
    )


class RecvMessageUtils(SecureChannelUtils):

  """Helper to receive the message."""

  def recv_message(self) -> api.Message:
    """Receives the message synchronously, verifies and decrypts the message."""
    message = self.channel._data_source.read()
    self._decrypt_and_verify_message_in_place(message)
    return message

  def _verify_message_id(self, message: api.Message):
    self.channel._session_state.verify_recv_message_number(message.message_id)

  def _decrypt_message_in_place(self, message):
    cipher = BACKEND.create_cipher_mode(
      key=self.channel.extended_keys.send_encryption_key,
      ctr=message.message_id,
      cipher=self.channel.crypto_config.block_cipher,
      direction=Direction.DECRYPT
    )

    decrypted_data = cipher.update(message.data)
    decrypted_hmac = cipher.update(message.hmac)
    message.data, message.hmac = decrypted_data, decrypted_hmac

  def _verify_message_hmac(self, message: api.Message):
    key = self.channel.extended_keys.recv_sign_key
    hmac = self._get_data_hmac(message.message_id, message.data, key)
    hmac.verify(message.hmac)

  def _decrypt_and_verify_message_in_place(self, message):
    self._decrypt_message_in_place(message)
    self._verify_message_hmac(message)
    # Note: this needs to be called after we verified the hmac
    self._verify_message_id(message)

