# pylint: disable=missing-docstring, redefined-outer-name, invalid-name


import base64

import pytest

from secure_channel import api
from secure_channel import key_extension
from secure_channel.primitives import BACKEND


@pytest.fixture()
def alternate_session_key():
  sha = BACKEND.create_hash("SHA-256")
  sha.update(b'This sentence is false')
  return sha.finalize()


@pytest.fixture()
def alice_alternate_keys(alternate_session_key):
  return key_extension.DefaultKeyExtensionFunction().extend_keys(
    api.CommunicationSide.ALICE, alternate_session_key,
  )


def test_key_size(alice_keys):
  for key in alice_keys:
    assert len(key) == 32


def test_keys_swapped(alice_keys: api.ExtendedKeys, bobs_keys: api.ExtendedKeys):
  assert alice_keys.send_sign_key == bobs_keys.recv_sign_key
  assert alice_keys.recv_sign_key == bobs_keys.send_sign_key
  assert alice_keys.send_encryption_key == bobs_keys.recv_encryption_key
  assert alice_keys.recv_encryption_key == bobs_keys.send_encryption_key


def test_expected_values(alice_keys: api.ExtendedKeys):
  # Test for expected values, these shouldn't change.
  # They were generated on my computer.

  def compare_key(key, expected):
    assert base64.b64encode(key) == expected

  compare_key(alice_keys.send_sign_key, b'glqgVpNp2pj0/gkvjVnGdUG1A/QipO25ex1HAsG3s3w=')
  compare_key(alice_keys.send_encryption_key, b'e8/yw2pIRJm6s60Cg96vMo/ph03NM3WsXRmIQO5E5cA=')
  compare_key(alice_keys.recv_encryption_key, b'XoVzhPAJDnhSl4922Z14vDLEAa/230tsWsMJ2iKjkG4=')
  compare_key(alice_keys.send_encryption_key, b'e8/yw2pIRJm6s60Cg96vMo/ph03NM3WsXRmIQO5E5cA=')


def test_different_session_keys_generate_different_extended_keys(alice_keys, alice_alternate_keys):
  # This one works as follows, extended keys are a named tuple, which is a tuple
  # so we add both of these tuples to a set, and check if there are duplicates.
  raw_keys = set()
  raw_keys.update([bytes(k) for k in alice_keys])
  raw_keys.update([bytes(k) for k in alice_alternate_keys])
  assert len(raw_keys) == 8
