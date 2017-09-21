from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import hmac

from secure_channel.exceptions import InvalidSignature
from . import api, key_extension

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.algorithms import AES, BlockCipherAlgorithm
from cryptography.hazmat.primitives.hmac import HMAC
import cryptography.exceptions



DEFAULT_CRYPTO_CONFIG = api.ChannelCryptoConfiguration(
  protocol_version=1,
  session_key_length_bytes=32,
  block_cipher=AES,
  hash_algo=SHA256,
)


class SecureChannel(object):

  @property
  def block_size_bytes(self):
    return 32

  def __init__(
      self,
      data_source: api.DataSource,
      key_generator: api.SessionKeyNegotiator,
      *,
      crypto_configration: api.ChannelCryptoConfiguration=DEFAULT_CRYPTO_CONFIG,
      configuration: api.ChannelConfiguration=api.DEFAULT_CONFIGURATION,
  ):
    self.__data_source = data_source
    self.__configuration = configuration
    self.__crypto_config = crypto_configration
    self.__key_generator = key_generator

    self.__session_state = key_generator.create_session_state(
      self.__data_source,
      configuration
    )

  @property
  def config(self) -> api.ChannelConfiguration:
    return self.__configuration

  @property
  def crypto_config(self) -> api.ChannelCryptoConfiguration:
    return self.__crypto_config

  @property
  def extended_keys(self) -> api.ExtendedKeys:
    return self.__session_state.get_extended_keys()

  def __create_hmac(self) -> HMAC:
    return HMAC(
      bytes(self.extended_keys.send_sign_key),
      self.crypto_config.hash_algo(),
      backend=default_backend()
    )

  def construct_noonce(
      self,
      cipher: BlockCipherAlgorithm,
      message_id: int
  ):
    assert message_id < self.config.max_messages_in_session

    TODO: intentonaly broken syntax so I read this next time I

    # So here is the problem: I don't want to use canned CTR mode
    # of cryptography as security of the whole scheme depends on
    # details that are not in the documentation.

    # Here is the problem: for CTR to be secure we need to
    # contstruct key_stream using concatenation of message_id and
    # block id and some extra padding. However it looks like
    # CTR mode assumes noonce that is random, and I assume it
    # XORS noonce with block size. This won't work.

    # I want to make this excercise by the book so I'll need
    # to manually consteruct key-stream.



  def sign(self, data: api.DataBuffer) -> api.DataBuffer:
    hmac = self.__create_hmac()
    hmac.update(bytes(data))
    return hmac.finalize()

  def encrypt(self, data: api.DataBuffer, signature: api.DataBuffer) -> api.DataBuffer:


  def verify(self, data: api.DataBuffer, signature: api.DataBuffer):
    hmac = self.__create_hmac()
    hmac.update(bytes(data))
    try:
      hmac.verify(bytes(signature))
    except cryptography.exceptions.InvalidSignature as e:
      raise InvalidSignature() from e






