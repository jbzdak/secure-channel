
import typing

from . api import DataSource, DataBuffer, Message, ChannelConfiguration

from . import exceptions

class TestDataSource(DataSource):

  def __init__(
      self,
      config: ChannelConfiguration,
      in_messages: typing.Sequence[Message] = tuple()
  ):
    super().__init__(config)
    self.in_messages = in_messages
    self.__out_messages = []

  @property
  def in_messages(self) -> list:
    return list(reversed(self.__in_messages))

  @in_messages.setter
  def in_messages(self, in_messages):
    messages = list(in_messages)
    messages.reverse()
    self.__in_messages = messages

  @property
  def out_messages(self):
    return self.__out_messages

  def read(self) -> Message:
    return self.__in_messages.pop()

  def write(self, data: Message):
    self.__out_messages.append(data)



