"""Implements a secure channel."""

from secure_channel import api

from . import utils


class SecureChannel(object):

  """Implementation of secure channel."""

  @property
  def block_size_bytes(self):
    """Returns block size in bytes for this channel."""
    assert utils.CRYPTO_CONFIGURATION.hash_algo == "AES"
    return 16

  def __init__(
      self,
      data_source: api.DataSource,
      key_generator: api.SessionKeyNegotiator,
      *,
      crypto_configration: api.ChannelCryptoConfiguration = utils.CRYPTO_CONFIGURATION,
      configuration: api.ChannelConfiguration = api.DEFAULT_CONFIGURATION,
  ):
    self._data_source = data_source
    self._configuration = configuration
    self._crypto_config = crypto_configration
    self._key_generator = key_generator

    self._session_state = key_generator.create_session_state(
      self._data_source,
      configuration
    )

  def send_message(self, data: api.DataBuffer):
    """Sends the message."""
    send_utils = utils.SendMessageUtils(self)
    send_utils.send_message(data)

  def receive_message(self) -> bytearray:
    """Reads the message."""
    recv_message = utils.RecvMessageUtils(self)
    return recv_message.recv_message().data




