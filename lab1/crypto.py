#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: Incze Zoltan
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import math
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    chipertext = ""
    for letter in plaintext:
        if not letter.isalpha():
            chipertext += letter
        elif letter >= 'X':
            chipertext += chr(ord(letter) -23)
        else:
            chipertext += chr(ord(letter) + 3)
            
    return chipertext

def decrypt_caesar(ciphertext):
    plaintext = ""
    for letter in ciphertext:
        if not letter.isalpha():
            plaintext += letter
        elif letter <= 'C':
            plaintext += chr(ord(letter) + 23)
        else:
            plaintext += chr(ord(letter) - 3)

    return plaintext


def encrypt_vigenere(plaintext, keyword):
    new_keyword = ''
    i = 0
    for _ in plaintext:
        if i == len(keyword):
            i = 0
        new_keyword += keyword[i]
        i += 1
    
    cipertext = ""
    for letter, keyword_letter in zip(plaintext, new_keyword):
        if not letter.isalpha():
            cipertext += letter
        else:
            cipertext += chr((ord(letter) + ord(keyword_letter)) % 26 + 65)

    return cipertext


def decrypt_vigenere(ciphertext, keyword):
    new_keyword = ''
    i = 0
    for _ in ciphertext:
        if i == len(keyword):
            i = 0
        new_keyword += keyword[i]
        i += 1

    plaintext = ""
    for letter, keyword_letter in zip(ciphertext, new_keyword):
        if not letter.isalpha():
            plaintext += letter
        else:
            plaintext += chr((ord(letter) - (ord(keyword_letter))) % 26 + 65)

    return plaintext


def encrypt_scytale(plaintext, circumference):
    cipertexts = [''] * circumference
    i = 0
    while i < len(plaintext):
        for j in range(circumference):
            if i < len(plaintext):
                cipertexts[j] += plaintext[i]
                i += 1 
    return ''.join(cipertexts)
 
def decrypt_scytale(ciphertext, circumference):
    num_rows = math.ceil(len(ciphertext) / circumference)
    num_full_columns = len(ciphertext) % circumference
    
    rows = [''] * num_rows
    
    index = 0
    for column in range(circumference):
        for row in range(num_rows):
            if row < num_rows - 1 or column < num_full_columns or num_full_columns == 0:
                rows[row] += ciphertext[index]
                index += 1

    return ''.join(rows)

def encrypt_railfence(plaintext, num_rails):
    ciphertexts = num_rails * ['']
    i = 0
    j = 0
    while i < len(plaintext):
        for j in range(num_rails):
            if i < len(plaintext):
                ciphertexts[j] += plaintext[i]
                i += 1
            else:
                break
        for j in range(num_rails - 2, 0, -1):
            if i < len(plaintext):
                ciphertexts[j] += plaintext[i]
                i += 1
            else:
                break
    
    ciphertext = ''.join(ciphertexts)
    return ciphertext

def construct_matrix(num_rails, length):
    matrix = [['' for _ in range(length)] for _ in range(num_rails)]
    i = 0
    down = True
    for ind in range(length):
        matrix[i][ind] = '*'
        if down:
            i += 1
        else:
            i -= 1
        if i == 0 or i == num_rails - 1:
            down = not down
    return matrix

def decrypt_railfence(ciphertext, num_rails):
    matrix = construct_matrix(num_rails, len(ciphertext))

    index = 0
    for r in range(num_rails):
        for c in range(len(ciphertext)):
            if matrix[r][c] == '*' and index < len(ciphertext):
                matrix[r][c] = ciphertext[index]
                index += 1

    plaintext = []
    i = 0
    down = True
    for col in range(len(ciphertext)):
        plaintext.append(matrix[i][col])
        if down:
            i += 1
        else:
            i -= 1
        if i == 0 or i == num_rails - 1:
            down = not down

    return ''.join(plaintext)

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

