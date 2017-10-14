import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256, Hash

from secure_channel import key_extension, api


@pytest.fixture()
def session_key():
  sha = Hash(SHA256(), default_backend())
  sha.update(b'I love python and cryptography')
  sha.update(b'However I\'m proficient in only one of the above')
  return sha.finalize()


@pytest.fixture()
def alice_keys(session_key):
  return key_extension.DefaultKeyExtensionFunction().extend_keys(api.CommunicationSide.ALICE, session_key)


@pytest.fixture()
def bobs_keys(session_key):
  return key_extension.DefaultKeyExtensionFunction().extend_keys(api.CommunicationSide.BOB, session_key)

