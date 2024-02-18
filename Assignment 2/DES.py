'''
Project 0: You are required to develop a program to encrypt (and similarly decrypt) a 64-bit plaintext using DES. Instead of using 
an available library, I insist that you program any and every element of each of the 16 rounds of DES (and that means F-box, 32-
bit exchanges, generation of sub-key required in each round, etc.). Then, with at least THREE pairs of < plaintext, ciphertext>: 
a.  Verify that the ciphertext when decrypted will yield the original plaintext,  
b.  Verify that output of the 1st encryption round is same as output of the 15th decryption round as illustrated below, and 
c.  Verify that output of the 14th encryption round is same as the output of the 2nd decryption round as illustrated below. 
'''


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
          33, 1, 41,  9, 49, 17, 57, 25]

# Expansion Table
E = [32,  1,  2,  3,  4,  5,
      4,  5,  6,  7,  8,  9,
      8,  9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32,  1]

# Permutation Table
P = [16,  7, 20, 21, 29, 12, 28, 17,
      1, 15, 23, 26,  5, 18, 31, 10,
      2,  8, 24, 14, 32, 27,  3,  9,
     19, 13, 30,  6, 22, 11,  4, 25]

# Permutation Choice 1
PC1 = [57, 49, 41, 33, 25, 17,  9,
        1, 58, 50, 42, 34, 26, 18,
       10,  2, 59, 51, 43, 35, 27,
       19, 11,  3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
       14,  6, 61, 53, 45, 37, 29,
       21, 13,  5, 28, 20, 12,  4]

# Permutation Choice 2
PC2 = [14, 17, 11, 24,  1,  5,  3, 28,
       15,  6, 21, 10, 23, 19, 12,  4,
       26,  8, 16,  7, 27, 20, 13,  2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]


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
    # converting the 48-bit expanded half block to 8 6-bit blocks
    new_blocks = [expanded_half_block[i:i+6] for i in range(0, 48, 6)]

    for i in range(8):
        row = int(new_blocks[i][0] + new_blocks[i][5], 2)
        col = int(new_blocks[i][1:5], 2)
        s_box_outputs.extend([int(x) for x in format(s_boxes[i][row][col], '04b')])


        # row = int("".join(map(str, expanded_half_block[i * 6] + expanded_half_block[i * 6 + 5])), 2)
        # # print(f"Row: {row}")
        # col = int("".join(map(str, expanded_half_block[i * 6 + 1:i * 6 + 5])), 2)
        # # print(f"Col: {col}")
        # s_box_outputs.extend([int(x) for x in format(s_boxes[i][row][col], '04b')])
    # print(f"Length of s_box_outputs: {len(s_box_outputs)}")

    return ''.join(map(str, s_box_outputs))


def permutation(half_block):
    return permute(half_block, P)


def des_round(L, R, key):
    expanded_R = expansion_permutation(R) # Expands the 32-bit half block to 48 bits
    xor_output = xor(expanded_R, key) # Performs a bitwise XOR operation on the expanded half block and the key of length 48 bits
    substituted = substitution_boxes(xor_output) # Performs substitution using 8 S-boxes
    permuted = permutation(substituted) # Performs permutation using the P-box on length 32 bits
    new_R = xor(L, permuted)
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


def xor(block1, block2):
    """
    This function performs a bitwise XOR operation on two blocks.
    :param block1: First block
    :param block2: Second block
    :return: Resultant block after XOR operation
    """
    return ''.join(str(int(block1[i]) ^ int(block2[i])) for i in range(len(block1)))


def des_encryption(input_block, key, verifyRound = 0):
    """
    This function performs the DES encryption on the input block using the given key.
    :param input_block: 64-bit input block
    :param key: 64-bit key
    :return: 64-bit encrypted block
    """ 
    bin_key = string_to_binary(key)
    bin_input_block = string_to_binary(input_block)

    keys = generate_keys(bin_key) # Returns a list of 16 strings of 48 bits each
    
    plaintext = initial_permutation(bin_input_block)
    
    L, R = plaintext[:32], plaintext[32:]  # Splits the 64-bit plaintext into two 32-bit halves
    for i in range(16):
        L, R = des_round(L, R, keys[i])
        if verifyRound == i+1:
            verifyConcat = R + L
    
    encrypted_block = final_permutation(R + L) # Swaps the two halves and performs the final permutation
    encrypted_block = binary_to_string(encrypted_block)

    if verifyRound == 0:
        return encrypted_block
    else:
        return encrypted_block, verifyConcat


def des_decryption(input_block, key, verifyRound = 0):
    """
    This function performs the DES decryption on the input block using the given key.
    :param input_block: 64-bit input block
    :param key: 64-bit key
    :return: 64-bit decrypted block
    """
    bin_key = string_to_binary(key)
    bin_input_block = string_to_binary(input_block)
    
    keys = generate_keys(bin_key) # Returns a list of 16 strings of 48 bits each
    
    plaintext = initial_permutation(bin_input_block)
    
    L, R = plaintext[:32], plaintext[32:]  # Splits the 64-bit plaintext into two 32-bit halves
    for i in range(15, -1, -1):
        L, R = des_round(L, R, keys[i])
        if verifyRound == i+1:
            verifyConcat = R + L
    
    decrypted_block = final_permutation(R + L) # Swaps the two halves and performs the final permutation
    decrypted_block = binary_to_string(decrypted_block)
    
    if verifyRound == 0:
        return decrypted_block
    else:
        return decrypted_block, verifyConcat


def verify_rounds(plaintext, ciphertext, key, round1, round2): 
    keys = generate_keys(string_to_binary(key))
    new_plaintext = initial_permutation(string_to_binary(plaintext))
    L, R = new_plaintext[:32], new_plaintext[32:]
    for i in range(16):
        L, R = des_round(L, R, keys[i])
        if i == round1-1:
            verify_encrypt = R + L
            break
    
    new_ciphertext = initial_permutation(string_to_binary(ciphertext))
    L, R = new_ciphertext[:32], new_ciphertext[32:]
    for i in range(15, -1, -1):
        L, R = des_round(L, R, keys[i])
        if i == round2-1:
            verify_decrypt = R + L
            break

    if verify_encrypt == verify_decrypt:
        print(f"Verification successful! Output of round {round1} encryption round is same as output of round {round2} decryption round.")
        print(f"Output of {round1}: {verify_encrypt}")
    else:
        print(f"Verification failed! Output of round {round1} encryption round is not same as output of round {round2} decryption round.")
        print(f"Output of round {round1} encryption round: {verify_encrypt}")
        print(f"Output of round {round2} decryption round: {verify_decrypt}")


def get_key():
    key = None

    while True:
        key = input("Enter a secret key (8 bytes only): ")
        if len(key) != 8:
            print("Invalid key length. Key should be 8 bytes long.")
        else:
            break
    
    return key


def main_menu():
    print('----------------------------------------------------------')
    print("1. Encryption\n2. Decryption\n3. Verification\n4. Exit")
    choice = int(input("Enter your choice: "))
    print('----------------------------------------------------------')
    return choice


def interactive_menu():
    choice = main_menu()
    while choice != 4:
        if choice == 1:
            plaintext = input("Enter plaintext: ")
            key = get_key()
            ciphertext = des_encryption(plaintext, key)
            print(f"Ciphertext: {ciphertext}")

        elif choice == 2:
            ciphertext = input("Enter ciphertext: ")
            key = get_key()
            plaintext = des_decryption(ciphertext, key)
            print(f"Plaintext: {plaintext}")

        elif choice == 3:
            plaintext = input("Enter plaintext: ")
            key = get_key()

            ciphertext = des_encryption(plaintext, key)
            decrypted_plaintext = des_decryption(ciphertext, key)

            print(f"Decrypted plaintext: {decrypted_plaintext}")

            if plaintext == decrypted_plaintext:
                print("Decryption successful!")
            else:
                print("Decryption failed!")
            
        else:
            print("Invalid choice!")

        choice = main_menu()


if __name__ == "__main__":
    print('----------------------------------------------------------')
    print("Encrypting & Decrypting Plaintexts Using DES Algorithm!")
    print('----------------------------------------------------------')
    print("1. Interactive Mode")
    print("2. File Mode")
    print('----------------------------------------------------------')
    choice = int(input("Enter your choice: "))
    print('----------------------------------------------------------')

    if choice == 1:
        interactive_menu()
    
    elif choice == 2:
        # read a file that contains plaintexts
        file = open("Assignment 2/plaintext.txt", "r")
        plaintexts = file.readlines()
        plaintexts = [x.strip() for x in plaintexts]
        file.close()

        # # read a file that contains ciphertexts
        # cipher_file = open("Assignment 2/ciphertext.txt", "w+")
        # ciphertexts = cipher_file.readlines()
        # ciphertexts = [x.strip() for x in ciphertexts]

        # read a file that contains keys
        keys_file = open("Assignment 2/keys.txt", "r")
        keys = keys_file.readlines()
        keys = [x.strip() for x in keys]
        keys_file.close()

        for i in range(len(plaintexts)):
            key = keys[i]
            plaintext = plaintexts[i]
            
            ciphertext = des_encryption(plaintext, key)
            # cipher_file.write(string_to_binary(ciphertext) + "\n")
            print(f"Plaintext: {plaintext}\nCiphertext: {ciphertext}\n")

            decrypted_plaintext = des_decryption(ciphertext, key)
            print(f"Decrypted plaintext: {decrypted_plaintext}\n")

            if plaintext == decrypted_plaintext:
                print("Decryption successful!")
            else:
                print("Decryption failed!")
            
            # verify the 1st encryption round is same as output of the 15th decryption round
            first_fifteen = verify_rounds(plaintext, ciphertext, key, 1, 15)
            print('----------------------------------------------------------')
        # cipher_file.close()

    else:
        print("Invalid choice!")
    print('----------------------------------------------------------')
