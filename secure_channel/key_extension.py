
from Crypto.Hash import SHA256

from .api import ExtendedKeys, KeyExtensionFunction
from .utils import clear_buffer




class DefaultKeyExtensionFunction(KeyExtensionFunction):
  """
  Default KeyExtensionFunction, it generates key by using SHA-256
  hash on concatenation of session key and unique message
  for each direction and sign/encrypt.
  """

  @classmethod
  def encrypt_key_size(cls) -> int:
    return 32

  @classmethod
  def sign_key_size(cls) -> int:
    return 32

  def do_hash(self, message: bytes):
    hash_obj = SHA256.new()
    hash_obj.update(message)
    hash_obj.update(self.session_key)
    return bytearray(hash_obj.digest())

  def extend_keys(self) -> ExtendedKeys:
    extended_keys = ExtendedKeys(
      send_encryption_key=self.do_hash(b'Encrypt Alice to Bob'),
      recv_encryption_key=self.do_hash(b'Encrypt Bob to Alice'),
      send_sign_key=self.do_hash(b'Sign Alice to Bob'),
      recv_sign_key=self.do_hash(b'sign Bob to Alice'),
    )
    return self._swap_keys_for_bob(extended_keys)
