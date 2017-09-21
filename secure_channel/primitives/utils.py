

def constant_time_compare(a: bytearray, b: bytearray) -> bool:
  """
  Constant time compare.
  """

  assert isinstance(a, bytearray)
  assert isinstance(b, bytearray)

  if len(a) != len(b):
    return False

  result = [None] * len(a)
  for ii, (ea, eb) in enumerate(zip(a, b)):
    result[ii] = int(ea ^ eb)

  return sum(result) == 0


