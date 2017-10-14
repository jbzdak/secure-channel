# pylint: disable=missing-docstring, redefined-outer-name, invalid-name

import pytest

from secure_channel import data_source, secure_channel, api, key_negotiation


@pytest.fixture()
def channel_sources():
  return (
    data_source.TestDataSource(api.DEFAULT_CONFIGURATION, []),
    data_source.TestDataSource(api.DEFAULT_CONFIGURATION, [])
  )


@pytest.fixture()
def key_generators(session_key):
  return (
    key_negotiation.TestSessionKeyNegotiator(
      session_key,
      api.CommunicationSide.ALICE
    ),
    key_negotiation.TestSessionKeyNegotiator(
      session_key,
      api.CommunicationSide.BOB
    )
  )


@pytest.fixture(params=[0, 1])
def channels(request, channel_sources, key_generators):
  return (
    secure_channel.SecureChannel(
      data_source=channel_sources[request.param],
      key_generator=key_generators[request.param]
    ),
    secure_channel.SecureChannel(
      data_source=channel_sources[1 if request.param == 0 else 0],
      key_generator=key_generators[1 if request.param == 0 else 0]
    )
  )


@pytest.fixture()
def channel(channel_sources, key_generators):
  return secure_channel.SecureChannel(
    data_source=channel_sources[0],
    key_generator=key_generators[0]
  )
