
import typing

from . api import DataSource, DataBuffer, Message, ChannelConfiguration

from . import exceptions

class TestDataSource(DataSource):

  def __init__(self, config: ChannelConfiguration, in_messages: typing.Sequence[Message], ):
    super().__init__(config)
    self.__in_messages = list(in_messages)
    self.__in_messages.reverse()
    self.__out_messages = []

  @property
  def out_messages(self):
    return self.__out_messages

  def read(self) -> Message:
    return self.__in_messages.pop()

  def write(self, data: Message):
    self.__out_messages.append(data)



