
import hashlib
import hmac
import os

import pytest

from secure_channel.exceptions import InvalidSignature


@pytest.fixture()
def hmac_key():
  return b"example key"

@pytest.fixture()
def fixed_message():
  return b"Attack at NORTH at DAWN."


@pytest.fixture()
def fixed_message_hash():
  return bytearray.fromhex(
    "21bc97fcb61a8d1c34a2412cfdc73b4cbc875587bb070224b0516a8f68bd3f87"
  )


@pytest.fixture()
def fixed_message_invalid_hash():
  return bytearray.fromhex(
    "21bd97fcb61a8d1c34a2412cfdc73b4cbc875587bb070224b0516a8f68bd3f87"
  )


@pytest.fixture()
def pure_python_hmac(hmac_key):
  def hmac_impl(message):
    h = hmac.HMAC(hmac_key, message, digestmod=hashlib.sha256)
    return h.digest()
  return hmac_impl


@pytest.fixture()
def pycrypto_hmac(hmac_key, pycrypto_backend):
  def hmac_impl(message):
    hmac = pycrypto_backend.create_hmac(key=hmac_key, hash="SHA-256")
    hmac.update(message)
    return hmac.finalize()
  return hmac_impl


@pytest.fixture()
def pycrypto_hmac_verifier(hmac_key, pycrypto_backend):
  def hmac_impl(message, signature):
    hmac = pycrypto_backend.create_hmac(key=hmac_key, hash="SHA-256")
    hmac.update(message)
    assert hmac.verify(signature) is None
  return hmac_impl


def test_python_hmac(fixed_message, fixed_message_hash, pure_python_hmac):
  """Test that our pure python implementation works"""
  assert fixed_message_hash == pure_python_hmac(fixed_message)


def test_pycrypto_hmac(fixed_message, fixed_message_hash, pycrypto_hmac):
  """Test pycrypto implementation using known hashes."""
  assert fixed_message_hash == pycrypto_hmac(fixed_message)


def test_pycrypto_hmac_verifier(fixed_message, fixed_message_hash, pycrypto_hmac_verifier):
  """Test pycrypto verifier"""
  pycrypto_hmac_verifier(fixed_message, fixed_message_hash)


def test_pycrypto_hmac_verifier_negative(fixed_message, fixed_message_invalid_hash, pycrypto_hmac_verifier):
  """Test pycrypto verifier raises on invalid hash"""
  with pytest.raises(InvalidSignature):
    pycrypto_hmac_verifier(fixed_message, fixed_message_invalid_hash)


@pytest.fixture(params=list(range(100)))
def random_test_data():
  buffer = bytearray(os.urandom(1024))
  return buffer


@pytest.mark.test
def random_tests_for_pycrypto_hmac(random_test_data, pure_python_hmac, pycrypto_hmac):
  assert pure_python_hmac(bytes(random_test_data)) == pycrypto_hmac(bytes(random_test_data))




