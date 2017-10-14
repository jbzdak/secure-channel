"""Exception classes."""


class BaseCryptoException(Exception):
  """
  Base exception class.

  Please **don't** propagate any exception details to message recipients!
  """


class FatalException(Exception):
  """
  Base class for fatal exceptions
  """


class AlreadyReseted(FatalException):
  """
  Raised when secure state was already cleared.
  """



class NotEnoughDataInInput(BaseCryptoException):
  """
  Thrown when there is not enough data in input stream we are reading from.
  """


class RecvMessageOutOfSequence(FatalException):
  """
  Thrown when received message id is less or equal to last received
  message number
  """

class NeedToRenegotiateKey(BaseCryptoException):
  """
  Thrown when you need to renegotiate key, due to using up all messages
  in session.
  """


class InvalidSignature(BaseCryptoException):
  """
  A signature is invalid
  """

class CounterOverflowError(BaseCryptoException):
  """
  A counter has overflown.
  """
