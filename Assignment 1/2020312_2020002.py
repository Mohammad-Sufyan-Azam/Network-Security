'''
a. You are required to develop executable programs to encrypt, decrypt, and more importantly launch brute-
force attack to discover the key, 

b. The difference between the three projects are (i) the character set and the manner of crafting the plaintext, 
(ii) the specific encryption/decryption algorithm you will use, and (iii) the method for launching a brute force attack, 

c. In Project 0 the character set is {A, B, C}. In projects Project 1 and Project 2, the character set consists of 
lower case English letters, viz. {a, b, ..., z}. In all cases the plaintext you will work with should be “recognizable”.  
To make the text recognizable, the plaintext p should satisfy some property, π, that can be checked by an algorithm or a 
program and declare whether π(p) =true or false. This property π can take different forms. The simplest form where 
plaintext == original_text ||original_text, where || is the concatenation operator, will not work. Therefore, you should 
identify or construct a good hash function Hash(.) that you may use to construct a plaintext, p = (string, Hash(string)), 
where “string” is the original text. The Hash function should be such that the received or decrypted string can be 
recognized by an algorithm or program. 
'''
import hashlib
import random
import numpy as np
import time
import sys
from termcolor import colored

def generate_hash_value(text):    # using sha256 hash function
    return hashlib.sha256(text.encode()).hexdigest()


def generate_key():
    key_len = random.randint(5, 9)
    key = ""
    # generate key_len unique random digits ranging between 0 to key_len-1
    while len(key) < key_len:
        digit = str(random.randint(0, key_len-1))
        if digit not in key:
            key += digit
    return key


# def generate_key():
#     key_len = random.randint(5, 9)
#     key = ""
#     # generate key_len unique random digits ranging between 0 to key_len-1
#     while len(key) < key_len:
#         digit = str(random.randint(0, 9))
#         if digit not in key:
#             key += digit
#     return key


def generate_new_plain_text(plain_text, key_length, hash_length=64):
    '''Adds the required garbage characters to the plaintext for filling the transposition matrix.
    new_plain_text = plain_text + garbage_characters'''
    characters_present = len(plain_text) + hash_length + 1      # +1 for the "#" character
    garbage_characters = key_length - characters_present % key_length

    new_plain_text = plain_text + "."*garbage_characters
    return new_plain_text


def transposition_matrix(new_plain_text, key, encrypt=True):
    '''Returns the transposition matrix of the new_plain_text'''
    n_cols = len(key)
    n_rows = len(new_plain_text) // n_cols

    if encrypt:
        matrix = []
        for i in range(n_rows):
            matrix.append(list(new_plain_text[i*n_cols:(i+1)*n_cols]))

    else:
        # Create a numpy array of size n_rows x n_cols
        matrix = np.empty((n_rows, n_cols), dtype=str)
        key_list = list(map(int, str(key)))
        ordered_indices = np.argsort(key_list)

        # Extract the packets from the cipher text to fill column
        for i in range(n_cols):
            matrix[:, ordered_indices[i]] = list(new_plain_text[i*n_rows:(i+1)*n_rows])            

    return matrix


def order_matrix_indices(key):
    ''' Returns the list of columns of the matrix in the order specified by the key'''
    order_indices = []
    
    for i in key:
        order_indices.append((int(i), key.index(i)))

    order_indices.sort()

    return order_indices


def encrypt(plain_text, key):
    '''Calculates the hash value of the new_plain_text and appends it to the new_plain_text.
    Encrypts the message using the key and returns the cipher_text
    to_be_encrypted = plain_text + garbage_characters + "#" + hash_value'''

    # key = generate_key()
    new_plain_text = generate_new_plain_text(plain_text, len(key))
    hash_value = generate_hash_value(new_plain_text)

    print('New plain text: ' + new_plain_text)
    print('Hash value: ' + hash_value)
    print('Key: ' + key)

    to_be_encrypted = new_plain_text + "#" + hash_value
    cipher_text = ""

    print('Message to be encrypted: ' + to_be_encrypted)

    matrix = transposition_matrix(to_be_encrypted, key)
    # print("Transposition matrix: ")
    # for row in matrix:
    #     print(row)
    
    ordered_indices = order_matrix_indices(key)

    for i in range(len(key)):
        for j in range(len(matrix)):
            cipher_text += matrix[j][ordered_indices[i][1]]


    return cipher_text


def decrypt(cipher_text, key):
    '''Decrypts the cipher_text using the key and returns the decrypted_text.
    Removes the hash value from the decrypted_text and returns it.'''

    decrypted_text = ""
    matrix = transposition_matrix(cipher_text, key, encrypt=False)

    # Flatten the transposition matrix
    decrypted_text = ''.join(matrix.flatten())
    # print(decrypted_text)

    split_index = decrypted_text.rfind("#")
    hash_value = decrypted_text[split_index+1:]
    decrypted_text = decrypted_text[:split_index]

    valid = verify_decrypted_text(decrypted_text, hash_value)

    return decrypted_text, hash_value, valid


def verify_decrypted_text(decrypted_text, hash_value):
    '''Returns True if the hash value of the decrypted_text matches the hash_value passed as argument.
    Returns False otherwise.'''

    return generate_hash_value(decrypted_text) == hash_value


def next_permutation(key):
    '''Returns the next permutation of the key passed as argument.'''
    key = list(key)
    bPoint, n = -1, len(key)
    for i in range(n-2,-1,-1):
        if key[i] >= key[i+1]: 
            continue
        bPoint = i
        for j in range(n-1,i,-1):
            if key[j] > key[bPoint]:
                key[j], key[bPoint] = key[bPoint], key[j]
                break
        break
    key[bPoint+1:] = reversed(key[bPoint+1:])
    key = "".join(key)
    return key


def brute_force_attack(cipher_text, key_len):
    first_key = ""
    first_key = "".join([str(i) for i in range(0, key_len)])
    # for i in range(0, key_len):
    #     first_key += str(i)
    
    last_key = ""
    for i in range(key_len-1, 0, -1):
        last_key += str(i)
    
    guess_key = first_key
    start_time = time.time()

    i = 0
    while True:
        # Assumption: hash value is always appended at the end of the plaintext. (There can be extra characters after plaintext and before hash value. Need to remove them.)
        # guess_key = "0" * (key_len - len(guess_key)) + guess_key
        decrypted_text, decrypted_hash_value, valid = decrypt(cipher_text, guess_key)
        
        print_word = "Guessing key: " + guess_key
        sys.stdout.write('\r' + "Guessing key: " + colored(guess_key, 'red'))
        sys.stdout.flush()
        # time.sleep(0.001)  # sleep for 1ms
        sys.stdout.write('\r' + ' '*len(print_word))
        i+=1


        if valid:
            end_time = time.time()
            print("\nKey found: " + colored(guess_key, 'green'))
            print(f"Time taken: {end_time-start_time} sec")
            print("Decrypted text: " + decrypted_text)
            print("Hash value: " + decrypted_hash_value)
            print("Number of keys tried: " + str(i))
            print("----------------------------------------\n")
            return guess_key
        
        guess_key = next_permutation(guess_key)

        if guess_key == last_key:
            print("All possible keys tried. Key not found.")
            break
        
    return "Key not found"


def main_menu():
    print("------------------------------------------------")
    print("Encryption using Transposition Cipher Program")
    print("------------------------------------------------")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Brute force attack")
    print("4. Exit")
    print("----------------------------------------\n")
    choice = int(input("Enter your choice: "))
    print("----------------------------------------\n")
    return choice


def main():

    choice = main_menu()
    # choice = 1
    while choice != 4:
        if choice == 1:
            file_name = input("Enter the name of the file containing the plain text: ")
            # file_name = "input.txt"
            f = open(file_name, "r")
            plain_text = f.read().split("\n")
            f.close()

            print("Encryption starts.....")
            f1 = open("cipher_text.txt", "w")
            f2 = open("keys.txt", "w")

            for msg in plain_text:
                print("Plain text: " + msg)
                key = generate_key()
                cipher_text = encrypt(msg, key)
                print("Encrypted text: " + cipher_text)
                print("Key: " + key)
                print("----------------------------------------\n")

                f1.write(cipher_text + "\n")
                f2.write(key + "\n") 
            f1.close()
            f2.close()

            print("Encryption ends.....\n\n")
            # choice = 2

        if choice == 2:
            f = open(input("Enter the name of the file containing the cipher text: "), "r")
            # f = open("cipher_text.txt", "r")
            f2 = open("keys.txt", "r")
            encrypted_text = f.read().split("\n")
            encrypted_text = [i for i in encrypted_text if i != '']
            keys = f2.read().split("\n")
            keys = [i for i in keys if i != '']

            f.close()

            print("Decryption starts.....")
            f1 = open("decrypted_text.txt", "w")

            for i in range(len(encrypted_text)):
                print("Encrypted text: " + encrypted_text[i])
                print("Key: " + keys[i])
                decrypted_text, hash_value, valid = decrypt(encrypted_text[i], keys[i])
                print("Decrypted text: " + decrypted_text)
                # print("Calculated Hash Value: " + generate_hash_value(decrypted_text))
                print("Hash value: " + hash_value)
                print("Valid: " + str(valid))
                print("----------------------------------------\n")

                f1.write(decrypted_text + "\n")
                f1.write(hash_value + "\n")

            f1.close()
            print("Decryption ends.....\n\n")

        elif choice == 3:
            f = open(input("Enter the name of the file containing the cipher text: "), "r")
            f2 = open("keys.txt", "r")
            encrypted_text = f.read().split("\n")
            encrypted_text = [i for i in encrypted_text if i != '']
            key_len = f2.read().split("\n")
            key_len = [len(i.strip()) for i in key_len]
            key_len = [i for i in key_len if i >= 3 and i <= 9]

            f.close()
            f2.close()

            print("Brute force attack starts.....")
            f1 = open("brute_force_attack.txt", "w")

            for i in range(len(encrypted_text)):
                print("Encrypted text: " + encrypted_text[i])
                print("Key length: " + str(key_len[i]))
                key = brute_force_attack(encrypted_text[i], key_len[i])
                print("----------------------------------------\n")

                f1.write(key + "\n")

            f1.close()
            print("Brute force attack ends.....\n\n")
        
        choice = main_menu()


if __name__ == "__main__":
    main()
