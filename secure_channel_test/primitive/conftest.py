# pylint: disable=missing-docstring, redefined-outer-name, invalid-name


import pytest


@pytest.fixture(scope="module")
def pycrypto_backend():
  from secure_channel.primitives import pycrypto_backend
  return pycrypto_backend.PycryptoBackend()


