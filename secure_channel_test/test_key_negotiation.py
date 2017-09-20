

import pytest

from secure_channel import key_negotiation, utils

@pytest.fixture()
def test_key_negotiator(session_key):
  return key_negotiation.TestSessionKeyNegotiator(session_key)


def test_key_negotiator_equals(session_key, test_key_negotiator):
  assert session_key == test_key_negotiator.create_session_key(None)


def test_key_negotiator_copies_data(session_key, test_key_negotiator):
  assert session_key is not test_key_negotiator.create_session_key(None)

  session_key1 = test_key_negotiator.create_session_key(None)
  session_key2 = test_key_negotiator.create_session_key(None)

  utils.clear_buffer(session_key1)

  assert session_key2 == session_key

