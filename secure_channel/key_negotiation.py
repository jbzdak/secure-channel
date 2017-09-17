from . api import SessionKeyNegotiator

WIP WIP
class DefaultSessionKeyNegotiator(SessionKeyNegotiator):
  """
  This is totally unsafe and usable only during tests.
  """

  def create_session_key(self, sess) -> bytes:
    return super().create_session_key()
