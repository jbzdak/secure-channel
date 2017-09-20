from secure_channel.api import DataSource
from . api import SessionKeyNegotiator


class TestSessionKeyNegotiator(SessionKeyNegotiator):
  """
  This is totally unsafe and usable only during tests.
  """

  def __init__(self, key: bytes):
    self.key = key

  def create_session_key(self, source: DataSource) -> bytearray:
    return bytearray(self.key)

