'''
Project 0: You are required to develop a program to encrypt (and similarly decrypt) a 64-bit plaintext using DES. Instead of using 
an available library, I insist that you program any and every element of each of the 16 rounds of DES (and that means F-box, 32-
bit exchanges, generation of sub-key required in each round, etc.). Then, with at least THREE pairs of < plaintext, ciphertext>: 
a.  Verify that the ciphertext when decrypted will yield the original plaintext,  
b.  Verify that output of the 1st encryption round is same as output of the 15th decryption round as illustrated below, and 
c.  Verify that output of the 14th encryption round is same as the output of the 2nd decryption round as illustrated below. 
'''

import numpy as np


def string_to_binary(s):
    return ''.join(format(ord(i), '08b') for i in s)

def binary_to_string(b):
    return ''.join(chr(int(b[i:i + 8], 2)) for i in range(0, len(b), 8))

def hex_to_binary(h):
    return bin(int(h, 16))[2:].zfill(64)

def binary_to_hex(b):
    return hex(int(b, 2))[2:].zfill(16)


# Defining constants

# Initial Permutation Table
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17,  9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Inverse Initial Permutation Table
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Table
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Permutation Table
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Permutation Choice 1
PC1 = [57, 49, 41, 33, 25, 17,  9,
        1, 58, 50, 42, 34, 26, 18,
       10,  2, 59, 51, 43, 35, 27,
       19, 11,  3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
       14,  6, 61, 53, 45, 37, 29,
       21, 13,  5, 28, 20, 12,  4]
# print(max(PC1), min(PC1), len(PC1))
# Permutation Choice 2
PC2 = [14, 17, 11, 24,  1,  5,  3, 28,
       15,  6, 21, 10, 23, 19, 12,  4,
       26,  8, 16,  7, 27, 20, 13,  2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]
# print(max(PC2), min(PC2), len(PC2))
# Shift Table
shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def permute(data, table):
    return ''.join([data[i-1] for i in table])


def generate_keys(key):
    """
    This function generates 16 subkeys, each of which is 48-bits long.
    :param key: 64-bit cipher key in bits format
    :return: List of 16 48-bit keys
    """
    keys = []
    key = permute(key, PC1) # Returns a 56-bit key after performing the permutation
    # print(f"Length of key after PC1: {len(key)}")
    C, D = key[:28], key[28:] # Splits the 56-bit key into two 28-bit halves
    for i in range(16):
        # Perform left circular shift on C and D. For rounds 1,2,9,16 shift by 1, for all others shift by 2
        if i in [0, 1, 8, 15]:
            C = C[1:] + C[:1]
            D = D[1:] + D[:1]
        else:
            C = C[2:] + C[:2]
            D = D[2:] + D[:2]
        CD = C + D # Concatenates the two 28-bit halves to form a 56-bit key
        keys.append(permute(CD, PC2)) # Performs another permutation to generate a 48-bit key
    # print(f"Length of key after PC2: {len(keys[0])}")
    return keys


def initial_permutation(input_block):
    return permute(input_block, IP)

def expansion_permutation(half_block):
    return permute(half_block, E)

def substitution_boxes(expanded_half_block):
    s_boxes = [
        # S1    
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],

        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],

        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],

        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],

        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],

        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],

        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],

        # S8 
        [
            [12, 4, 6, 1, 15, 7, 10, 8, 3, 13, 14, 5, 0, 11, 2, 9],
            [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
            [4, 10, 1, 7, 9, 5, 0, 13, 14, 2, 11, 12, 6, 8, 15, 3],
            [2, 15, 12, 9, 5, 6, 10, 11, 7, 8, 13, 14, 0, 3, 4, 1]
        ]
    ]



    s_box_outputs = []
    for i in range(8):
        row = int("".join(map(str, expanded_half_block[i * 6] + expanded_half_block[i * 6 + 5])), 2)
        # print(f"Row: {row}")
        col = int("".join(map(str, expanded_half_block[i * 6 + 1:i * 6 + 5])), 2)
        # print(f"Col: {col}")
        s_box_outputs.extend([int(x) for x in format(s_boxes[i][row][col], '04b')])
    # print(f"Length of s_box_outputs: {len(s_box_outputs)}")

    return ''.join(map(str, s_box_outputs))


def permutation(half_block):
    return permute(half_block, P)


def des_round(L, R, key):
    expanded_R = expansion_permutation(R) # Expands the 32-bit half block to 48 bits
    # print("Expanded R: ", expanded_R, len(expanded_R))
    xor_output = xor(expanded_R, key) # Performs a bitwise XOR operation on the expanded half block and the key of length 48 bits
    # print("XOR output: ", xor_output, len(xor_output))
    substituted = substitution_boxes(xor_output) # Performs substitution using 8 S-boxes
    # print("Substituted: ", substituted, len(substituted))
    permuted = permutation(substituted) # Performs permutation using the P-box on length 32 bits
    # print("Permuted: ", permuted, len(permuted))
    new_R = xor(L, permuted)
    # print("New R: ", new_R, len(new_R))
    return R, new_R

 
def initial_permutation(input_block):
    """
    This function performs the initial permutation on the input block.
    :param input_block: 64-bit input block
    :return: 64-bit permuted block
    """
    return permute(input_block, IP)


def final_permutation(input_block):
    """
    This function performs the final permutation on the input block.
    :param input_block: 64-bit input block
    :return: 64-bit permuted block
    """
    return permute(input_block, IP_INV)


def expand_half_block(half_block):
    """
    This function expands a 32-bit half block to 48 bits using the expansion table.
    :param half_block: 32-bit half block
    :return: 48-bit expanded block
    """
    pass

def xor(block1, block2):
    """
    This function performs a bitwise XOR operation on two blocks.
    :param block1: First block
    :param block2: Second block
    :return: Resultant block after XOR operation
    """
    return ''.join(str(int(block1[i]) ^ int(block2[i])) for i in range(len(block1)))

def s_box_substitution(expanded_half_block):
    """
    This function performs substitution on the expanded half block using 8 S-boxes.
    :param expanded_half_block: 48-bit expanded half block
    :return: 32-bit substituted block
    """
    pass

def p_box_permutation(half_block):
    """
    This function performs permutation on the half block using the P-box.
    :param half_block: 32-bit half block
    :return: 32-bit permuted block
    """
    pass


def des_encryption(input_block, key):
    """
    This function performs the DES encryption on the input block using the given key.
    :param input_block: 64-bit input block
    :param key: 64-bit key
    :return: 64-bit encrypted block
    """ 
    bin_key = string_to_binary(key)
    bin_input_block = string_to_binary(input_block)

    keys = generate_keys(bin_key) # Returns a list of 16 strings of 48 bits each
    # print("Key generation complete. Length of each key: ", len(keys[0]))
    
    # plaintext = initial_permutation(bin_input_block)
    plaintext = bin_input_block
    # print("Initial permutation complete. Length of plaintext: ", len(plaintext))
    
    L, R = plaintext[:32], plaintext[32:]  # Splits the 64-bit plaintext into two 32-bit halves
    # print("Splitting complete. Length of L: ", len(L))
    for i in range(16):
        L, R = des_round(L, R, keys[i])
    
    # encrypted_block = final_permutation(R + L) # Swaps the two halves and performs the final permutation
    encrypted_block = R + L
    print("Encryption complete. Length of encrypted block: ", len(encrypted_block))
    
    return encrypted_block


def des_decryption(input_block, key):
    """
    This function performs the DES decryption on the input block using the given key.
    :param input_block: 64-bit input block
    :param key: 64-bit key
    :return: 64-bit decrypted block
    """
    bin_key = string_to_binary(key)
    bin_input_block = string_to_binary(input_block)

    keys = generate_keys(bin_key) # Returns a list of 16 strings of 48 bits each
    # print("Key generation complete. Length of each key: ", len(keys[0]))
    
    # plaintext = initial_permutation(bin_input_block)
    plaintext = bin_input_block
    # print("Initial permutation complete. Length of plaintext: ", len(plaintext))
    
    L, R = plaintext[:32], plaintext[32:]  # Splits the 64-bit plaintext into two 32-bit halves
    # print("Splitting complete. Length of L: ", len(L))
    for i in range(15, -1, -1):
        L, R = des_round(L, R, keys[i])
    
    # decrypted_block = final_permutation(R + L) # Swaps the two halves and performs the final permutation
    decrypted_block = R + L
    print("Decryption complete. Length of decrypted block: ", len(decrypted_block))
    
    return decrypted_block


encrypt = des_encryption("helloabc", "helloabc")
print("Ciphertext:", binary_to_string(encrypt))
decrypt = des_decryption(encrypt, "helloabc")
print("Decrypted text:", binary_to_string(decrypt))