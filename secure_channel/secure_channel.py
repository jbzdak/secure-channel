
from . import api, key_extension


class ChannelState(object):
  def __init__(
    self,
    configuration: api.ChannelConfiguration = api.DEFAULT_CONFIGURATION
  ):
    self.__configuration = configuration


#
# class SecureChannel(object):
#
#   @property
#   def block_size_bytes(self):
#     return 32
#
#   def __init__(
#       self,
#       data_source,
#       key_generator: api.InitialKeyNegotiator
#       key_extension: api.KeyExtensionFunction=key_extension.DefaultKeyExtensionFunction,
#       configuration: api.ChannelConfiguration=api.DEFAULT_CONFIGURATION
#   ):
#     self.__data_source = data_source
#     self.__configuration = configuration
#
#
#   def write_bytes(self, data: api.DataBuffer):

