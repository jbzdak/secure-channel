import pytest

from secure_channel.exceptions import CounterOverflowError
from secure_channel.primitives.pycrypto_backend import format_counter


def test_format_counter():
  assert format_counter(1) == b'\0\0\0\0\0\0\0\1'
  assert format_counter(2) == b'\0\0\0\0\0\0\0\2'
  assert format_counter(256) == b'\0\0\0\0\0\0\1\0'
  assert format_counter((2 ** (8*8))-1) == bytearray.fromhex(
    "ff" * 8
  )

def test_format_counter_negative():
  with pytest.raises(CounterOverflowError):
    format_counter((2 ** (8*8)))
  with pytest.raises(CounterOverflowError):
    format_counter((2 ** (8*9)))
