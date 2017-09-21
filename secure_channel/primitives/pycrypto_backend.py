
import struct

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC

from .. import exceptions
from . import api
from .utils import constant_time_compare


__LONG_LONG_MAX = 2 ** (8 * 8)


def format_counter(counter: int):
  if counter > __LONG_LONG_MAX:
    raise exceptions.CounterOverflowError()
  return struct.pack(">Q", counter)


class PyCryptoHMAC(api.HMAC):

  def __init__(self, digestmod, key: bytearray):
    self.hmac = HMAC.HMAC(
      key=key,
      digestmod=digestmod
    )

  def verify(self, signature: bytearray):
    hmac_result = self.finalize()
    if not constant_time_compare(hmac_result, signature):
      raise exceptions.InvalidSignature()

  def update(self, data: bytearray):
    return self.hmac.update(data)

  def finalize(self) -> bytearray:
    return bytearray(self.hmac.digest())


class PyCryptoCipherMode(api.CipherMode):

  def __init__(
      self,
      cipher,
      message_id:int,
      key: bytearray
  ):
    self.cipher = cipher
    self.mode = cipher.new(
      key=key,
      mode=self.cipher.MODE_CTR,
      noonce=format_counter(message_id)
    )

  def update(self, data: api.DataBuffer) -> bytearray:
    assert len(data) % self.cipher.block_size == 0

    if not isinstance(data, bytearray):
      data = bytearray(data)

    return super().update(data)




class PycryptoBackend(api.Backend):
  def create_cipher_mode(self, key: bytearray, iv: bytearray, cipher: bytearray):
    return super().create_cipher_mode(key, iv, cipher)

  def create_hmac(self, key: bytearray, hash: str) -> HMAC:
    assert hash == "SHA-256"

    return super().create_hmac(key, hash)
