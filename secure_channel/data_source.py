"""Implementations of data source."""
import typing

from .api import DataSource, Message, ChannelConfiguration


class TestDataSource(DataSource):
  """Data source for testing purposes only."""
  def __init__(
      self,
      config: ChannelConfiguration,
      in_messages: typing.Sequence[Message] = tuple()
  ):
    super().__init__(config)
    self.__in_messages = None
    self.in_messages = in_messages
    self.__out_messages = []

  @property
  def in_messages(self) -> list:
    """
    Return list of messages that can be read using ``read`` function.
    """
    return list(reversed(self.__in_messages))

  @in_messages.setter
  def in_messages(self, in_messages):
    """
    Sets messages that can be read by secure channel.
    """
    messages = list(in_messages)
    messages.reverse()
    self.__in_messages = messages

  @property
  def out_messages(self):
    """Messages sent by secure channel."""
    return self.__out_messages

  def read(self) -> Message:
    return self.__in_messages.pop()

  #                                  some kind of false-positive
  def write(self, data: Message):  # pylint: disable=arguments-differ
    self.__out_messages.append(data)



