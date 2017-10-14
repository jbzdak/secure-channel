
import os

import pytest

from secure_channel.primitives.utils import constant_time_compare


@pytest.fixture(params=list(range(100)))
def random_buffer(request):
  buffer = bytearray(os.urandom(request.param))
  return buffer


@pytest.fixture(params=list(range(100)))
def two_buffers(request):
  a = None
  b = None

  while a == b:
    a = bytearray(os.urandom(request.param))
    b = bytearray(os.urandom(request.param))

    return a, b


def test_equal(random_buffer):
  a = bytearray(random_buffer)
  b = bytearray(random_buffer)
  assert constant_time_compare(a, b)
  # Test a and b were not modified
  assert random_buffer == a
  assert random_buffer == b


def test_not_equal(two_buffers):
  a = bytearray(two_buffers[0])
  b = bytearray(two_buffers[1])
  assert (a == b) == constant_time_compare(a, b)
  assert two_buffers[0] == a
  assert two_buffers[1] == b


