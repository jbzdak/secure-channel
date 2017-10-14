# pylint: disable=missing-docstring, redefined-outer-name, invalid-name

from random import SystemRandom

import pytest

from secure_channel.primitives.example import ctr_plaintext, ctr_plaintext_short


@pytest.fixture(params=list(range(100)))
def random_ints_4_bytes(srandom: SystemRandom):
  return srandom.getrandbits(4 * 8), srandom.getrandbits(4 * 8)


def test_both_plaintexts_agree(random_ints_4_bytes):
  a, b = random_ints_4_bytes
  assert ctr_plaintext_short(a, b) == ctr_plaintext(a, b)


def test_known_value_1():
  expected = b'\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02'
  assert ctr_plaintext(message_id=1, key_id=2) == expected


def test_known_value_2():
  expected = b'\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00'
  assert ctr_plaintext(message_id=256, key_id=1024) == expected
