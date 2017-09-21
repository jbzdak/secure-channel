

import pytest

import os

from secure_channel import utils, key_extension, api

@pytest.fixture(params=list(range(100)))
def random_buffer(request):
  buffer = bytearray(os.urandom(request.param))
  return buffer


def test_clear_buffer(random_buffer):
  utils.clear_buffer(random_buffer)
  for elem in random_buffer:
    assert elem == 0


def test_clear_keys(random_buffer):
  keys = key_extension.DefaultKeyExtensionFunction().extend_keys(
    api.CommunicationSide.ALICE, random_buffer
  )
  utils.destroy_key(keys)
  for key in keys:
    for elem in key:
      assert elem == 0


