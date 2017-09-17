import threading

from .api import SessionState, ConfigurationAware, ChannelConfiguration, DataBuffer, KeyExtensionFunction, ExtendedKeys

from . import exceptions, utils


class DefaultSessionState(SessionState):
  def __init__(
      self,
      configuration: ChannelConfiguration,
      key: ExtendedKeys,
      send_message_number: int = 0,
      recv_message_number: int = 0,
  ) -> None:
    super().__init__(configuration)
    self.__lock = threading.Lock()
    self.__send_message_number = send_message_number
    self.__recv_message_number = recv_message_number
    self.__extended_keys = key

  def __assert_ready(self):
    if self.__extended_keys is None:
      raise exceptions.AlreadyReseted()

  def get_send_message_number(self):
    with self.__lock:
      self.__assert_ready()
      self.__send_message_number+=1
      if self.__send_message_number >= self.configuration.max_messages_in_session:
        raise exceptions.NeedToRenegotiateKey()
      return self.__send_message_number

  def reset(self):
    with self.__lock:
      if self.__extended_keys is not None:
        utils.destroy_key(self.__extended_keys)
      self.__send_message_number = self.configuration.max_messages_in_session
      self.__recv_message_number = self.configuration.max_messages_in_session
      self.__extended_keys = None

  def get_extended_keys(self) -> ExtendedKeys:
    with self.__lock:
      self.__assert_ready()
      return self.__extended_keys

  def verify_recv_message_number(self, message_number: int):
    with self.__lock:
      self.__assert_ready()
      if message_number <= self.__recv_message_number:
        raise exceptions.RecvMessageOutOfSequence()
      if message_number >= self.configuration.max_messages_in_session:
        raise exceptions.NeedToRenegotiateKey()
      self.__recv_message_number = message_number




