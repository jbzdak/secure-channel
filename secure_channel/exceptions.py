


class BaseException(Exception):
  """
  Base exception class.

  Please **don't** propagate any exception details to message recipients!
  """


class NotEnoughDataInInput(BaseException):
  """
  Thrown when there is not enough data in input stream we are reading from.
  """
