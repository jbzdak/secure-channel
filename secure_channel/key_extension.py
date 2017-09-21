from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hashes import Hash

from .api import ExtendedKeys, KeyExtensionFunction, CommunicationSide, DataBuffer
from .utils import clear_buffer




class DefaultKeyExtensionFunction(KeyExtensionFunction):
  """
  Default KeyExtensionFunction, it generates key by using SHA-256
  hash on concatenation of session key and unique message
  for each direction and sign/encrypt.
  """

  def do_hash(self, session_key: DataBuffer, message: bytes):
    hash_obj = Hash(SHA256(), default_backend())
    # TODO: In the book these two were in different order
    # thing about it.
    hash_obj.update(bytes(message))
    hash_obj.update(bytes(session_key))
    return bytearray(hash_obj.finalize())

  def extend_keys(
      self,
      side: CommunicationSide,
      session_key: bytearray
  ) -> ExtendedKeys:
    extended_keys = ExtendedKeys(
      send_encryption_key=self.do_hash(session_key, b'Encrypt Alice to Bob'),
      recv_encryption_key=self.do_hash(session_key, b'Encrypt Bob to Alice'),
      send_sign_key=self.do_hash(session_key, b'Sign Alice to Bob'),
      # TODO: Fix first letter should be uppercase
      # but this will break tests
      recv_sign_key=self.do_hash(session_key, b'sign Bob to Alice'),
    )
    return self._swap_keys_for_bob(side, extended_keys)


