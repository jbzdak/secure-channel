# How CTR mode works

We work with 16 byte block sized ciphers. 

There are two counters: 

1. Message counter 
2. Block counter

Message counter globally counts messages 
encrypted with the same symmetric keys. 

Block counters add blocks in the message. 

For encryoption we use: 

    C_i = P_i xor K_i
    
where C_i is a block of ciphertext, P_i block of 
plaintext K_i is a block of keystream produced 
by following formula

    K_i = AES(Key, KC_i)
    
Where Key is a AES key, and KC_i is a counter block.        


Counter block is 16 byte long and 
contains 8 byte message key and 8 byte block counters. Both counters are 
little endian, and unsigned. 

If you don't like working with 8 byte integers
feel free to use four byte ones, but insert
zeroes in appropriate places. 

Formally bytes for this block can be obtained 
using: 

    def ctr_plaintext(message_id:int, key_id:int ):
      assert message_id < LONG_LONG_MAX
      assert key_id < LONG_LONG_MAX
      return struct.pack(">QQ", message_id, key_id)

