

import pytest

from secure_channel import key_negotiation, utils, api

@pytest.fixture()
def test_key_negotiator(session_key):
  return key_negotiation.TestSessionKeyNegotiator(
    session_key,
    api.CommunicationSide.ALICE
  )

@pytest.fixture()
def session_state(test_key_negotiator):
  return test_key_negotiator.create_session_state(None, api.DEFAULT_CONFIGURATION)


def test_key_negotiator_equals(alice_keys, session_state):
  assert session_state.get_extended_keys() == alice_keys


def test_key_negotiator_copies_data(session_state: api.SessionState):

  session_state.verify_recv_message_number(1)
  assert session_state.get_send_message_number() == 1

