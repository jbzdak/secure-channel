

from .api import DataBuffer, ExtendedKeys


def clear_buffer(buffer: DataBuffer):
  """Zeroes the buffer."""
  for ii in range(len(buffer)):
    buffer[ii] = 0


def destroy_key(key: ExtendedKeys):
  """Zeroes all elements in key."""
  for elem in key:
    clear_buffer(elem)

