"""
This calls for a little explanation.

So here is the deal:

* I really didn't want to create own primitives cryptography library,
  not for this project at least.
* However it looks like cryptography have some issues with CTR
  mode (I will explain this in depth in the next paragraph) and
  pycrypto seems to have two separate forks.
* Since I am not sure which of these libraries I will use in the end.
  I am totally fed up with switching back and forth between them.


My issues with ``cryptography`` package:

* CTR mode in this package does not specify how to safely create
  ``nonce`` from a counter. If nonce is not random it needs
  to be concatenated to as if it isn't attacker might defeat
  encryption;
* They use bytes for everything, which is bad since in
  "Cryptography Engineering: Design Principles and Practical Applications"
  there is explicit request to zero memory we use, and bytes
  can't be zeroed. (NOTE: the same can be said about pycrypto).
"""

from .api import Direction, CipherMode, HMAC, Backend, DataBuffer

from .pycrypto_backend import PycryptoBackend

BACKEND = PycryptoBackend()
