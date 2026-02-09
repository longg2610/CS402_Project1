from part1 import AES
import math
import random

mode = 1        # 0 for ECB, 1 for CTR

def text_to_bits(text: str, encoding="utf-8") -> str:
         data = text.encode(encoding)
         return ''.join(f'{byte:08b}' for byte in data)

# convert array representation to a binary string
def arr_to_bin(arr):
  bin_str = ""
  for col in range(4):
    for row in range(4):
        bin_str += format(arr[row][col], '08b')
  assert len(bin_str) == 128
  return bin_str

def ECB(plaintext_bits):
    # split the plaintext into 128-bit blocks, padded if needed
    # each block is encrypted independently using AES
    # ciphertext blocks are concatenated in the same order as the plaintext
    ciphertext_bits = ""
    block_size = 128
    i = 0

    while i < len(plaintext_bits):
        block = plaintext_bits[i:i + block_size]

        # pad for AES encryption if needed
        padded_block = block
        if len(block) < block_size:
            padded_block = block.ljust(block_size, '0')

        encrypted_block = AES.encryptBlock(padded_block)
        encrypted_bits = arr_to_bin(encrypted_block)

        # only append original block length (CTR-style behavior)
        ciphertext_bits += encrypted_bits[:len(block)]

        i += block_size

    assert len(ciphertext_bits) == len(plaintext_bits)
    return ciphertext_bits


# Generate all IVs needed
def genIV(plaintext_len):
  IV_count = math.ceil(plaintext_len / 128)
  IV_list = []

  IV = random.getrandbits(128)
  for _ in range(IV_count):
    IV += 1
    IV_list.append(text_to_bits(str(IV)))
  return IV_list

def CTR(plaintext_bits):
    IV_list = genIV(len(plaintext_bits))
    ciphertext_bits = ""
    block_size = 128  # AES block size
    i = 0
    counter = 0
    while i < len(plaintext_bits):
      block = plaintext_bits[i:i + block_size]
      IV_str = ""
      encrypted_IV = AES.encryptBlock(IV_list[counter])

      # convert encrypted IV from array representation to bit string so we can do XOR
      for j in range(4):
        for k in range(4):
           IV_str += format(encrypted_IV[j][k], '08b')    # make sure 8 bits are appended each time
      assert len(IV_str) == block_size

      IV_str = IV_str[0:len(block)]   # chop off last IV bits if block is not 128

      XOR_result = int(IV_str, 2) ^ int(block, 2)   # convert to int to do XOR
      ciphertext_bits += format(XOR_result, '0128b')[-len(block):]   # convert back to string, cut out only the necessary bits

      i += block_size
      counter += 1

    assert len(plaintext_bits) == len(ciphertext_bits)
    return ciphertext_bits

def encrypt(mode, msg):
    if mode == 0:
        return ECB(text_to_bits(msg))
    elif mode == 1:
        return CTR(text_to_bits(msg))


print("The message All Denison students should take CS402! encrypted is")
print(encrypt(mode, "All Denison students should take CS402!"))

print("ECB:")
print(ECB(text_to_bits("All Denison students should take CS402!")))