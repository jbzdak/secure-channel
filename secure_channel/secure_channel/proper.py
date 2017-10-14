from secure_channel import api

from . import utils

class CryptoDetailsSerializedForm(object):

  def __init__(self, crypto_configuration: api.ChannelCryptoConfiguration):
    self.field_names = crypto_configuration._fields
    self.field_types = crypto_configuration._field_types
    self.data = tuple(crypto_configuration)

class SecureChannel(object):

  @property
  def block_size_bytes(self):
    assert utils.CRYPTO_CONFIGURATION.hash_algo == "AES"
    return 16

  def __init__(
      self,
      data_source: api.DataSource,
      key_generator: api.SessionKeyNegotiator,
      *,
      crypto_configration: api.ChannelCryptoConfiguration=utils.CRYPTO_CONFIGURATION,
      configuration: api.ChannelConfiguration=api.DEFAULT_CONFIGURATION,
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
    u = utils.SendMessageUtils(self)
    u.send_message(data)

  def receive_message(self) -> bytearray:
    u = utils.RecvMessageUtils(self)
    return u.recv_message().data




