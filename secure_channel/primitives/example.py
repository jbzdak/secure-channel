"""This contains example code """


import struct

LONG_LONG_MAX = 2 ** (8 * 8)


def ctr_plaintext(message_id, key_id):
  """Create plaintext for counter key-stream."""
  assert message_id < LONG_LONG_MAX
  assert key_id < LONG_LONG_MAX
  return struct.pack(">QQ", message_id, key_id)


LONG_MAX = 2 ** (8 * 4)

def ctr_plaintext_short(message_id, key_id):
  """
  Create plaintext for counter key-stream.

  Version for 4 byte longs.
  """
  assert message_id < LONG_MAX
  assert key_id < LONG_MAX
  return struct.pack(">IIII", 0, message_id, 0, key_id)
