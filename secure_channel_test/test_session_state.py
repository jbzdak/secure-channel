
import pytest

from secure_channel import session_state as session_state_module, api, exceptions


@pytest.fixture()
def session_state(alice_keys):
  return session_state_module.DefaultSessionState(
    configuration=api.DEFAULT_CONFIGURATION,
    key=alice_keys,
    send_message_number=0,
    recv_message_number=0
  )


def test_extended_keys(alice_keys, session_state):
  assert session_state.get_extended_keys() is alice_keys

def test_session_reset(session_state: api.SessionState):
  session_state.reset()
  with pytest.raises(exceptions.AlreadyReseted):
    session_state.get_extended_keys()
  with pytest.raises(exceptions.AlreadyReseted):
    session_state.get_send_message_number()
  with pytest.raises(exceptions.AlreadyReseted):
    session_state.verify_recv_message_number(0)


def test_session_can_reset_twice(session_state: api.SessionState):
  session_state.reset()
  session_state.reset()


def test_session_reset_resets(session_state: api.SessionState):
  session_state.reset()
  assert session_state._DefaultSessionState__send_message_number \
         == session_state.configuration.max_messages_in_session
  assert session_state._DefaultSessionState__recv_message_number \
         == session_state.configuration.max_messages_in_session
  assert session_state._DefaultSessionState__extended_keys is None


def test_session_keys_cleared(session_state: api.SessionState):
  key_reference = session_state._DefaultSessionState__extended_keys
  session_state.reset()
  for part in key_reference:
    for elem in part:
      assert elem == 0


def test_get_send_message_number(session_state):
  assert session_state.get_send_message_number() == 1
  assert session_state.get_send_message_number() == 2
  assert session_state.get_send_message_number() == 3


def test_get_send_message_number_over_max(session_state):
  session_state._DefaultSessionState__send_message_number = \
    session_state.configuration.max_messages_in_session + 1

  with pytest.raises(exceptions.NeedToRenegotiateKey):
    session_state.get_send_message_number()


def test_get_send_message_number_equal_max(session_state):
  session_state._DefaultSessionState__send_message_number = \
    session_state.configuration.max_messages_in_session + 1

  with pytest.raises(exceptions.NeedToRenegotiateKey):
    session_state.get_send_message_number()


def test_verify_recv_message_number(session_state):
  session_state.verify_recv_message_number(1)
  session_state.verify_recv_message_number(2)
  session_state.verify_recv_message_number(3)


def test_verify_recv_message_number_can_skip_msgs(session_state):
  session_state.verify_recv_message_number(1)
  session_state.verify_recv_message_number(20)
  session_state.verify_recv_message_number(30)


def test_verify_recv_message_number_zero_invalid(session_state):
  with pytest.raises(exceptions.RecvMessageOutOfSequence):
    session_state.verify_recv_message_number(0)


def test_verify_recv_mesage_number_invalid_sequence(session_state):
  session_state.verify_recv_message_number(1)
  with pytest.raises(exceptions.RecvMessageOutOfSequence):
    session_state.verify_recv_message_number(1)


def test_verify_recv_mesage_number_invalid_sequence_2(session_state):
  session_state.verify_recv_message_number(10)
  with pytest.raises(exceptions.RecvMessageOutOfSequence):
    session_state.verify_recv_message_number(1)


def test_verify_recv_message_number_need_to_renegotiate_key(session_state):
  session_state.verify_recv_message_number(
    session_state.configuration.max_messages_in_session-1
  )
  with pytest.raises(exceptions.NeedToRenegotiateKey):
    session_state.verify_recv_message_number(
      session_state.configuration.max_messages_in_session
    )
