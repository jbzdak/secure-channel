"""Implementation of key negotiation."""

from .api import (
  SessionKeyNegotiator,
  DataSource,
  KeyExtensionFunction,
  CommunicationSide,
  SessionState,
  ChannelConfiguration
)

from .key_extension import DefaultKeyExtensionFunction
from .session_state import DefaultSessionState


class TestSessionKeyNegotiator(SessionKeyNegotiator):
  """
  This is totally unsafe and usable only during tests.
  """

  def __init__(
      self,
      key: bytes,
      side: CommunicationSide,
      kef: KeyExtensionFunction = None,
  ):
    if kef is None:
      kef = DefaultKeyExtensionFunction()
    self.key = key
    self.kef = kef
    self.side = side

  def create_session_state(
      self,
      data_source: DataSource,
      configuration: ChannelConfiguration
  ) -> SessionState:
    return DefaultSessionState(
      configuration,
      self.kef.extend_keys(self.side, bytearray(self.key)),
    )
