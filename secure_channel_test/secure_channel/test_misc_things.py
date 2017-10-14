# pylint: disable=missing-docstring, redefined-outer-name, invalid-name, protected-access


def test_channel_block_size(channel):
  assert channel.block_size_bytes == 16
