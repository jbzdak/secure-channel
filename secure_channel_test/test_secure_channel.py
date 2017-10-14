# pylint: disable=missing-docstring, redefined-outer-name, invalid-name

import pytest

from secure_channel import data_source, secure_channel, api, key_negotiation


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

