"""Implementation of key extension."""

from .api import ExtendedKeys, KeyExtensionFunction, CommunicationSide, DataBuffer

from .primitives import BACKEND


STATIC_KEY_FOR_KEY_EXTENSION = ""


class DefaultKeyExtensionFunction(KeyExtensionFunction):
  """
  Default KeyExtensionFunction, it generates key by using SHA-256
  hash on concatenation of session key and unique message
  for each direction and sign/encrypt.
  """

  @classmethod
  def _do_hash(cls, session_key: DataBuffer, message: bytes):
    hash_obj = BACKEND.create_hash("SHA-256")
    hash_obj.update(bytes(message))
    hash_obj.update(bytes(session_key))
    return bytearray(hash_obj.finalize())

  def extend_keys(
      self,
      side: CommunicationSide,
      session_key: bytearray
  ) -> ExtendedKeys:
    extended_keys = ExtendedKeys(
      send_encryption_key=self._do_hash(session_key, b'Encrypt Alice to Bob'),
      recv_encryption_key=self._do_hash(session_key, b'Encrypt Bob to Alice'),
      send_sign_key=self._do_hash(session_key, b'Sign Alice to Bob'),
      # TODO: Fix first letter should be uppercase
      # but this will break tests
      recv_sign_key=self._do_hash(session_key, b'sign Bob to Alice'),
    )
    return self._swap_keys_for_bob(side, extended_keys)


