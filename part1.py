import random

seed = 1962481  # min(D# in your group)
random.seed(seed)

key = random.getrandbits(128)

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

DNums = "D01962481D01962564D01966755"

plaintext = text_to_bits(DNums)[:128]
print("Plaintext: " + str(plaintext))


class AES:
  
  SBox = [[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
[0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
[0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
[0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
[0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
[0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
[0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
[0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
[0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
[0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
[0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
[0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
[0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
[0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
[0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
[0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]
  

  # ============================================================ KEY EXPANSION =============================================

  def keyInit():
    key_byte_array = list(key.to_bytes(16, byteorder='big'))

    key_matrix = [[0 for __ in range (0, 4)] for _ in range(0, 4)]
    for i in range(16):
      key_matrix[i % 4][i // 4] = key_byte_array[i]
    return key_matrix
  
  def RotWord(word):
    first = word.pop(0)
    return word + [first]
    
  # do S-Box on 4 bytes at once
  def SubWord(word):
    new_word = []
    for i in range (len(word)):
      new_word.append(AES.SubBytes(word[i]))
    return new_word
  
  Rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]   # key expansion constants for each round
  def XOR(word1, word2):
    result = []
    for i in range(4):
      result.append(word1[i] ^ word2[i])
    return result

  def keyExpansion(key_matrix, i):
    lastWord = [key_matrix[r][3] for r in range(4)]   # last 4 bytes of the previous round key
    
    # rotate, then S-Box on every bytes, then XOR with the round's constant
    lastWord = AES.XOR(AES.SubWord(AES.RotWord(lastWord)), [AES.Rcon[i], 0x00, 0x00, 0x00])

    newKey = [[0]*4 for _ in range(4)]

    for r in range(4):
        newKey[r][0] = lastWord[r] ^ key_matrix[r][0]
    for r in range(4):
        newKey[r][1] = newKey[r][0] ^ key_matrix[r][1]
    for r in range(4):
        newKey[r][2] = newKey[r][1] ^ key_matrix[r][2]
    for r in range(4):
        newKey[r][3] = newKey[r][2] ^ key_matrix[r][3]

    return newKey
  
    ### TRANSFORMATIONS ###
  def SubBytes(input_byte):
    #split input into the 4 leftmost bits and the 4 rightmost bits
    #the leftmost bits are the row index and the rightmost bits are the column index
    #use SBox and return whatever's at that index

    row = (input_byte >> 4) & 0x0F   # top 4 bits
    col = input_byte & 0x0F          # bottom 4 bits

    return AES.SBox[row][col]

  def ShiftRows(input_matrix):
    #input is a 4x4 matrix of bytes
    #circular left shift by i where i is the row index
    #return new matrix
    for i in range(1, 4):
      for j in range(i):
        elem = input_matrix[i].pop(0)
        input_matrix[i].append(elem)
    return input_matrix
  
  A = [[2,3,1,1], [1,2,3,1], [1,1,2,3], [3,1,1,2]]    # const array used in MixColumns
  B = [[0x0E, 0x0B, 0x0D, 0x09], [0x09, 0x0E, 0x0B, 0x0D], [0x0D, 0x09, 0x0E, 0x0B], [0x0B, 0x0D, 0x09, 0x0E]]
  
  def MUL(const, input):
    if const == 1:
      return const * input
    elif const == 2:
        shift_left_one = input << 1
        if input & 0b10000000:      # if highest bit was 1
            shift_left_one ^= 0x1B
        return shift_left_one & 0xFF
    elif const == 3:
        shift_left_one = input << 1
        if input & 0b10000000:      # if highest bit was 1
            shift_left_one ^= 0x1B
        return (shift_left_one ^ input) & 0xFF

  def MixColumns(input_matrix):
    #4x4 matrix mult between const matrix A and input_matrix
    #A is defined on page 180 (6.3), need to figure out how to
    #matrix mult while using XOR as the addition operator

    result = [[0 for __ in range (0, 4)] for _ in range(0, 4)]
    for i in range(4):
      for j in range(4):
        for k in range(4):
          result[i][j] = result[i][j] ^ AES.MUL(AES.A[i][k], input_matrix[k][j])
    return result
    
  def AddRoundKey(input_matrix, round_key):
    #XOR cell i,j of input matrix with cell i,j of the round key
    output = [[0 for __ in range (0, 4)] for _ in range(0, 4)]
    for i in range(0, 4):
      for j in range(0, 4):
        output[i][j] = input_matrix[i][j] ^ round_key[i][j]
    return output
  

  def encryptBlock(plaintext, trace=False):
    #state = copy of plaintext in byte matrix
    #calculate round keys with keyExpansion()
    #addRoundKey
    #for i from 0 to 9:
    #   subBytes, shiftRows, mixColumns, addRoundKey
    #subBytes, shiftRows, addRoundKey
    #return state

    state = [[0 for __ in range (0, 4)] for _ in range(0, 4)]

    # initialize first state to be the plaintext input
    for i in range(16):
      state[i % 4][i // 4] = int(plaintext[8*i : 8*i+8], 2)

    # print("Plaintext: " + str(state))

    # initialize first key
    K_0 = AES.keyInit()

    # XOR initial state with initial key (K_0)
    state = AES.AddRoundKey(state, K_0)

    prev_key = K_0
    round_states = [ [row.copy() for row in state] ]  # store initial state

    #N = 10 (number of rounds) for 16-byte key
    for i in range(1, 10):
      # do SubBytes on the whole 128-bit blovk
      for j in range(4):
        state[j] = AES.SubWord(state[j])

      # ShiftRows
      state = AES.ShiftRows(state)
      
      # MixColumns
      state = AES.MixColumns(state)

      # AddRoundKey
      new_key = AES.keyExpansion(prev_key, i)
      state = AES.AddRoundKey(state, new_key)
      prev_key = new_key
      
      if trace:
         round_states.append([row.copy() for row in state])  # store state after each round

    #10th (final) round doesn't mix columns
    for j in range(4):
       state[j] = AES.SubWord(state[j])

    state = AES.ShiftRows(state)

    new_key = AES.keyExpansion(prev_key, 10)
    state = AES.AddRoundKey(state, new_key)

    if trace:
        round_states.append([row.copy() for row in state])  # store final state
        return state, round_states

    return state
  

  InvSBox = [[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
[0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
[0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
[0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
[0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
[0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
[0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
[0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
[0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
[0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
[0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
[0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
[0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
[0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
[0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
[0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]
  
  def decryptBlock(ciphertext, trace=False):
    #state = copy of ciphertext
    # --- everything is the same except use inv functions instead
    # --- round keys decrementing instead of incrementing
    #calculate round keys with keyExpansion()
    #addRoundKey
    #for i from 1 to 9:
    #   subBytes, shiftRows, mixColumns, addRoundKey
    #subBytes, shiftRows, addRoundKey
    #return state
    state = [[0 for __ in range (0, 4)] for _ in range(0, 4)]

    # initialize first state to be the ciphertext input
    for i in range(16):
      state[i % 4][i // 4] = int(ciphertext[8*i : 8*i+8], 2)

    # print("Plaintext: " + str(state))

    # initialize first key
    keys = [AES.keyInit()]
    for i in range(1,11):
      keys.append(AES.keyExpansion(keys[i-1], i))
    
    #[0, 10]

    # XOR initial state with initial key (K_0)
    state = AES.AddRoundKey(state, keys[10])

    round_states = [[row.copy() for row in state] ]  # store initial state

    #N = 10 (number of rounds) for 16-byte key
    for i in range(9, 0, -1):
      
      
      # ShiftRows
      state = AES.InvShiftRows(state)
      
      # SubBytes
      state = AES.InvSubBytes(state)
      
      # AddRoundKey
      state = AES.AddRoundKey(state, keys[i])
      
      # MixColumns
      state = AES.InvMixColumns(state)
      
      if trace:
         round_states.append([row.copy() for row in state])  # store state after each round

    #10th (final) round doesn't mix columns
    state = AES.InvShiftRows(state)
    
    state = AES.InvSubBytes(state)

    state = AES.AddRoundKey(state, keys[0])

    if trace:
        round_states.append([row.copy() for row in state])  # store final state
        return state, round_states

    return state
  
  def InvSubBytes(input_matrix):
    #split input into the 4 leftmost bits and the 4 rightmost bits
    #the leftmost bits are the row index and the rightmost bits are the column index
    #use InvSBox and return whatever's at that index
    result = [[0 for __ in range (0, 4)] for _ in range(0, 4)]
    for i in range(4):
      for j in range(4):
        byte = input_matrix[i][j]
        bits = bin(byte)[2:].zfill(8)
        row = int(bits[0:3], 2)
        col = int(bits[4:7], 2)
        result[i][j] = AES.InvSBox[row][col]
    return result
  
  def InvShiftRows(input_matrix):
    #input is a 4x4 matrix of bytes
    #circular right shift by i where i is the row index
    #return new matrix
    for i in range(1, 4):
      for j in range(i):
        elem = input_matrix[i].pop(-1)
        input_matrix[i].insert(0, elem)
    return input_matrix
  
  def InvMixColumns(input_matrix):
    #4x4 matrix mult between const matrix B and input_matrix
    #B is defined on page 181 (6.5), need to figure out how to
    #matrix mult while using XOR as the addition operator
    result = [[0 for __ in range (0, 4)] for _ in range(0, 4)]
    for i in range(4):
      for j in range(4):
        for k in range(4):
          result[i][j] = result[i][j] ^ AES.MUL(AES.B[i][k], input_matrix[k][j])
    return result

# test key expansion
# initialKey = AES.keyInit()
# round1Key = AES.keyExpansion(initialKey, 1)
# round2Key = AES.keyExpansion(round1Key, 2)
# print("K0: " + arr_to_bin(initialKey))
# print("K1: " + str(round1Key))
# print("K2: " + str(round2Key))

#enc = AES.encryptBlock(plaintext)
#enc_str = arr_to_bin(enc)


def main():
  # driver code: this part just return the ciphertext in bits
  enc = AES.encryptBlock(plaintext)
  enc_str = arr_to_bin(enc)
  print("Ciphertext: " + enc_str)


  # encrypt with tracing
  ciphertext, round_states = AES.encryptBlock(plaintext, trace=True)


  # print state after each round in hex
  def print_hex_str(round_states):
    for r, s in enumerate(round_states):
        print(f"State after round {r} (hex):")

        hex_str = ""
        for col in range(4):
            for row in range(4):
                hex_str += f"{s[row][col]:02x}"

        print(hex_str)
        print()

  print_hex_str(round_states)

  # flip bit 12 (leftmost MSB = 0)
  plaintext_bits = list(plaintext) 
  plaintext_bits[12] = '1' if plaintext_bits[12] == '0' else '0'
  plaintext_flipped = ''.join(plaintext_bits)

  # encrypt the modified plaintext
  ciphertext_flipped, round_states_flipped = AES.encryptBlock(plaintext_flipped, trace=True)
  print()
  print("Ciphertext after flipping bit: " + arr_to_bin(ciphertext_flipped))
  print_hex_str(round_states_flipped)

  # count bit differences
  for r in range(5):  
      state_orig = round_states[r]
      state_new  = round_states_flipped[r]

      diff_bits = 0
      for i in range(4):
          for j in range(4):
              diff_bits += bin(state_orig[i][j] ^ state_new[i][j]).count('1') # see which bits changed

      print(f"Round {r}: {diff_bits} bits differ")


main()