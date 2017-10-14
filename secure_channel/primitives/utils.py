"""Utility classes."""

import struct

from secure_channel import exceptions


def constant_time_compare(left: bytearray, right: bytearray) -> bool:
  """
  Constant time compare.
  """

  assert isinstance(left, bytearray)
  assert isinstance(right, bytearray)

  if len(left) != len(right):
    return False

  result = bytearray(len(right))
  for ii, (left_elem, right_elem) in enumerate(zip(left, right)):
    result[ii] = int(left_elem ^ right_elem)

  return sum(result) == 0


__LONG_LONG_MAX = 2 ** (8 * 8) - 1


def format_counter(counter: int) -> bytes:
  """Formats int counter to long long bytes"""
  if counter > __LONG_LONG_MAX:
    raise exceptions.CounterOverflowError()
  return struct.pack(">Q", counter)


