from random import SystemRandom

import pytest


@pytest.fixture(scope="module")
def pycrypto_backend():
  from secure_channel.primitives import pycrypto_backend
  return pycrypto_backend.PycryptoBackend()


@pytest.fixture(scope="module")
def srandom():
  return SystemRandom()

