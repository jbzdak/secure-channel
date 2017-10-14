# pylint: disable=missing-docstring, redefined-outer-name, invalid-name, protected-access

import pytest


@pytest.fixture()
def example_message():
  return b'\x10.A\x7f\x1d.\xdf3\x9cTd;\xa7\xd9\x8c\x1d\xe4' \
         b'\x11\xa3Q,\x9b\xbe\xd1m\xb3d\xed\xa3\xd0\xb63'


def connect_channels(channel_in, channel_out):
  channel_out._data_source.in_messages = channel_in._data_source.out_messages


def test_single_message_encryption(channel, example_message):
  channel.send_message(example_message)
  # TODO: Store message and verify id didn't change


def test_single_message_two_way_encryption(channels, example_message):
  channel1, channel2 = channels
  channel1.send_message(example_message)
  connect_channels(channel1, channel2)
  assert example_message == channel2.receive_message()


#
# def test_message_passing(channels, random_data_for_tests):
#   channel1, channel2 = channels
#   channel1.send_message(random_data_for_tests)
#   channel2._data_source.in_messages = channel1._data_source.out_messages
#   data = channel2.recv_message()
#   assert data == random_data_for_tests

