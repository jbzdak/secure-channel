"""Misc utils,"""

from .api import DataBuffer, ExtendedKeys


def clear_buffer(buffer: DataBuffer):
  """Sets all bytes in the buffer to zero."""
  for ii in range(len(buffer)):  # pylint: disable=consider-using-enumerate
    buffer[ii] = 0


def destroy_key(key: ExtendedKeys):
  """Sets all bytes in all keys to zero."""
  for elem in key:
    clear_buffer(elem)
