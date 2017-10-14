
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Counter, Padding

from . import api
from .utils import constant_time_compare, format_counter
from .. import exceptions


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
      key: bytearray,
      direction: api.Direction,
      raw_nonce=None
  ):
    self.cipher = cipher
    self.direction = direction

    if raw_nonce is not None:
      ctr = Counter.new(
        128,
        initial_value=int.from_bytes(raw_nonce, byteorder='big', signed=False)
      )
    else:
      ctr = Counter.new(
        64,
        prefix=format_counter(message_id),
        initial_value=0
      )

    if isinstance(key, bytearray):
      # TODO: ensure keys can be securely removed from memory.
      key = bytes(key)

    self.mode = cipher.new(
      key=key,
      mode=self.cipher.MODE_CTR,
      counter=ctr
    )

  def update(self, data: api.DataBuffer) -> bytearray:
    assert len(data) % self.cipher.block_size == 0

    if not isinstance(data, bytes):
      data = bytes(data)

    if self.direction == api.Direction.ENCRYPT:
      response = self.mode.encrypt(data)
    else:
      response = self.mode.decrypt(data)

    return response

  @property
  def block_size_bytes(self) -> int:
    return AES.block_size

  def pad(self, data) -> bytearray:
    return Padding.pad(data, self.block_size_bytes)

  def unpad(self, data) -> bytearray:
    return Padding.unpad(data, self.block_size_bytes)



class PycryptoBackend(api.Backend):

  def create_cipher_mode(
      self,
      key: bytearray,
      ctr: int,
      cipher: str,
      direction: api.Direction
  ):
    assert cipher == "AES"
    assert len(key) == (256 / 8)

    return PyCryptoCipherMode(
      cipher=AES, message_id=ctr, key=key, direction=direction)

  def create_hmac(self, key: bytearray, hash: str) -> HMAC:
    assert hash == "SHA-256"
    return PyCryptoHMAC(SHA256, key)

