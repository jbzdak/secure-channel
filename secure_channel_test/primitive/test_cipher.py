

import os
from random import SystemRandom

import pytest

from secure_channel.primitives.api import Direction, Backend


@pytest.fixture()
def fixed_key():
  return bytearray.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
  )

@pytest.fixture()
def init_counter():
  return bytearray.fromhex(
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
  )


@pytest.fixture()
def plaintext():
  return bytearray.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
  )


@pytest.fixture()
def ciphertext():
  return bytearray.fromhex(
    "601ec313775789a5b7a7f504bbf3d228"
    "f443e3ca4d62b59aca84e990cacaf5c5"
    "2b0930daa23de94ce87017ba2d84988d"
    "dfc9c58db67aada613c2dd08457941a6"
  )


@pytest.fixture()
def pycrypto_fixed_strings_cipher(fixed_key, init_counter):
  from secure_channel.primitives.pycrypto_backend import PyCryptoCipherMode
  from Crypto.Cipher import AES

  return PyCryptoCipherMode(
    cipher=AES,
    message_id=None,
    key=fixed_key,
    direction=Direction.ENCRYPT,
    raw_nonce=init_counter,
  )


def test_fixed_string_encryption(pycrypto_fixed_strings_cipher, plaintext, ciphertext):
  actual = pycrypto_fixed_strings_cipher.update(plaintext)
  assert ciphertext == actual


def test_fixed_string_decryption(pycrypto_fixed_strings_cipher, plaintext, ciphertext):
  pycrypto_fixed_strings_cipher.direction = Direction.DECRYPT
  actual = pycrypto_fixed_strings_cipher.update(ciphertext)
  assert plaintext == actual


@pytest.fixture()
def random_key():
  return os.urandom(32)

@pytest.fixture(params=range(10))
def random_message_id(srandom, request):
  if request.param == 0:
    return 0
  if request.param == 1:
    return int.from_bytes(bytearray.fromhex("ffffffff"), byteorder='big', signed=False)
  return srandom.randint(1, 4294967296-1)


@pytest.fixture(params=range(100))
def random_data_for_tests(srandom: SystemRandom):
  block_count = srandom.randint(1, 1024)
  data_size = block_count * 32
  return os.urandom(data_size)


@pytest.fixture()
def pycrypto_ciphers(pycrypto_backend: Backend, random_key, random_message_id):
  encrypt = pycrypto_backend.create_cipher_mode(
    key = random_key,
    ctr = random_message_id,
    cipher="AES",
    direction=Direction.ENCRYPT
  )
  decrypt = pycrypto_backend.create_cipher_mode(
    key=random_key,
    ctr=random_message_id,
    cipher="AES",
    direction=Direction.ENCRYPT
  )

  return encrypt, decrypt


def test_encryption_and_decryption(pycrypto_ciphers, random_data_for_tests):
  encrypt, decrypt = pycrypto_ciphers
  plaintext = random_data_for_tests
  ciphertext = encrypt.update(plaintext)
  decrypted = decrypt.update(ciphertext)
  assert decrypted == plaintext
