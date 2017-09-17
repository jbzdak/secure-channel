
from secure_channel import key_extension, api

import pytest
from Crypto.Hash import SHA256


@pytest.fixture()
def session_key():
  sha = SHA256.new()
  sha.update(b'I love python and cryptography')
  sha.update(b'However I\'m proficient in only one of the above')
  return sha.digest()


@pytest.fixture()
def alice_keys(session_key):
  return key_extension.DefaultKeyExtensionFunction(session_key, api.CommunicationSide.ALICE).extend_keys()


@pytest.fixture()
def bobs_keys(session_key):
  return key_extension.DefaultKeyExtensionFunction(session_key, api.CommunicationSide.BOB).extend_keys()

