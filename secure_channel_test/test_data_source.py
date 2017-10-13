
import pytest

from secure_channel import api, data_source

def test_data_source_config():
  sd = data_source.TestDataSource(api.DEFAULT_CONFIGURATION, [])
  assert sd.config is api.DEFAULT_CONFIGURATION
  with pytest.raises(AttributeError):
    sd.config = api.DEFAULT_CONFIGURATION


def test_data_source_in_messages():
  # Technically they should be instances of Message class, but it don't cares what is inside this list.
  expected = [1, 2, 3, 4]
  sd = data_source.TestDataSource(api.DEFAULT_CONFIGURATION, list(expected))
  actual = [sd.read() for __ in expected]
  assert expected == actual

def test_data_source_write():
  sd = data_source.TestDataSource(api.DEFAULT_CONFIGURATION, [])
  expected = [1, 2, 3, 4]
  for item in expected:
    sd.write(item)
  assert sd.out_messages == expected


def test_data_source_in_messages_setter():
  # Technically they should be instances of Message class, but it don't cares what is inside this list.
  expected = [1, 2, 3, 4]
  sd = data_source.TestDataSource(api.DEFAULT_CONFIGURATION, list(expected))
  actual = [sd.read() for __ in expected]
  assert expected == actual
  expected = [5, 6, 8, 7]
  sd = data_source.TestDataSource(api.DEFAULT_CONFIGURATION, list(expected))
  actual = [sd.read() for __ in expected]
  assert expected == actual


def test_data_getter():
  # Technically they should be instances of Message class, but it don't cares what is inside this list.
  expected = [1, 2, 3, 4]
  sd = data_source.TestDataSource(api.DEFAULT_CONFIGURATION, list(expected))
  assert sd.read() == 1
  assert sd.in_messages == [2, 3, 4]

