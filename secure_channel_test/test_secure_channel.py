

from secure_channel import data_source, secure_channel, api, key_negotiation

import os

import pytest

@pytest.fixture()
def channel_source():
  return data_source.TestDataSource(api.DEFAULT_CONFIGURATION, [])


@pytest.fixture()
def key_generator(session_key):
  return key_negotiation.TestSessionKeyNegotiator(
    session_key,
    api.CommunicationSide.ALICE
  )


@pytest.fixture()
def channel(channel_source, key_generator):
  return secure_channel.SecureChannel(
    data_source=channel_source,
    key_generator=key_generator
  )


def test_sign_and_verify(channel: secure_channel.SecureChannel):
  test_message = os.urandom(channel.crypto_configuration.hash_algo.block_size)
  signature = channel.sign(test_message)
  channel.verify(test_message, signature)

