# pylint: disable=missing-docstring, redefined-outer-name, invalid-name
import os
from random import SystemRandom

import pytest

from secure_channel import key_extension, api
from secure_channel.primitives import BACKEND


@pytest.fixture()
def session_key():
  sha = BACKEND.create_hash("SHA-256")
  sha.update(b'I love python and cryptography')
  sha.update(b'However I\'m proficient in only one of the above')
  return sha.finalize()


@pytest.fixture()
def alice_keys(session_key):
  return key_extension.DefaultKeyExtensionFunction().extend_keys(
    api.CommunicationSide.ALICE, session_key)


@pytest.fixture()
def bobs_keys(session_key):
  return key_extension.DefaultKeyExtensionFunction().extend_keys(
    api.CommunicationSide.BOB, session_key
  )


@pytest.fixture(scope="session")
def srandom():
  return SystemRandom()


@pytest.fixture(params=range(100), scope="session")
def random_data_for_tests(srandom: SystemRandom):
  block_count = srandom.randint(1, 1024)
  data_size = block_count * 32
  return os.urandom(data_size)
