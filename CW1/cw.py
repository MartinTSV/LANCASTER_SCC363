
# Task 2 imports
import base64
from operator import xor
from re import L
import ssl
import hashlib
import sys
import OpenSSL

# Task3 imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_parameters, load_pem_public_key, load_pem_private_key

# Task 4 Imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Task1
# Implement encryption function of an Affine cipher


def encryptAffine(plainText, a, b):
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    cipherText = ""
    for x in plainText:
        if x in alphabet:
            x = (a*alphabet.index(x) + b) % 26
            cipherText = cipherText + alphabet[x]
        else:
            cipherText = cipherText + x
    return cipherText


# Task2
# Avalanche caluclator


def avalancheCalculator(string1, string2):
    leading_zeros = {
        "0": 4,
        "1": 3,
        "2": 2,
        "3": 2,
        "4": 1,
        "5": 1,
        "6": 1,
        "7": 1
    }
    avalancheNumber = 0
    hexValue1 = hashlib.sha256(string1.encode()).hexdigest()
    hexValue2 = hashlib.sha256(string2.encode()).hexdigest()
    # Convert hex1 to 0b
    binValue1 = bin(int(hexValue1, 16)).split('0b')
    binValue1 = binValue1[1]
    first_hex = list(hexValue1)[0]
    if first_hex in leading_zeros:
        binValue1 = '0' * leading_zeros.get(first_hex) + binValue1
    binValue1 = list(binValue1)
    # Convert hex2 to 0b
    binValue2 = bin(int(hexValue2, 16)).split('0b')  # Remove the 0b
    binValue2 = binValue2[1]
    first_hex = list(hexValue2)[0]  # find the first in hex
    if first_hex in leading_zeros:
        binValue2 = '0' * leading_zeros.get(first_hex) + binValue2
    binValue2 = list(binValue2)
    # Comparison
    i = 0
    while i < len(binValue1) and i < len(binValue2):
        if binValue1[i] != binValue2[i]:
            avalancheNumber = avalancheNumber + 1
        i = i + 1

    avalancheNumber = avalancheNumber + len(binValue1) - len(binValue2)
    print(avalancheNumber)
    return avalancheNumber


# Task 3
# Diffle_Hellman
# Imports
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import dh
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_parameters, load_pem_public_key, load_pem_private_key


def Diffie_Hellman():
    sent_pub_key = b'-----BEGIN PUBLIC KEY-----\nMIGaMFMGCSqGSIb3DQEDATBGAkEAz/nUjZwUcuI2x0769GHBJNGzM4rDMvqf5PVW\nAm/oDzVPzkg5JhF+tmCk3I9UKwKPPn93bv243X1Sn7+9S1rcYwIBAgNDAAJAYyRw\n2K7KvbqudRx9DQtKH/tAQjDtDMIw7hFWYslMFnE/t44wArXQ/wuo0NPhFL4b63R8\nJZA7cF7tP+CAj3WHFA==\n-----END PUBLIC KEY-----\n'
    dh_parameters = b'-----BEGIN DH PARAMETERS-----\nMEYCQQDP+dSNnBRy4jbHTvr0YcEk0bMzisMy+p/k9VYCb+gPNU/OSDkmEX62YKTc\nj1QrAo8+f3du/bjdfVKfv71LWtxjAgEC\n-----END DH PARAMETERS-----\n'

    # Diffle_Hellman
    dh_parameters = load_pem_parameters(dh_parameters)
    # Generate a private key based on dh parameters
    private_key = dh_parameters.generate_private_key()
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    # Load shared public key
    peer_public_key = serialization.load_pem_public_key(sent_pub_key)
    # Create shared_key
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32, salt=None, info=b'handshake data').derive(shared_key)

    return public_key_pem, derived_key
# Task 4
# Clues:
# 1. CiphertextA and messageA are provided
# 2. It is known that the same encryption key and initialization vector are used for subsequent encryptions.
# 3. Your task is to calculate the ciphertext of message B


def findCiphertext():
    ciphertextA = b"\xef@\x92<$J\xb2\x8c\xbc\xabl'\x016\xd2{W8\xcas\x83*\xa1\xef)\xc0\xda\x7fe\xab\xb1\x94\x7fJ\x98\xc8\xeei|'t\xb4"
    messageA = b"I'll give you 500 and that's my last offer."
    messageB = b"I'll give you 100 and that's my last offer."

    # XOR ciphertextA and messageA
    i = 0
    xor_msg_ciph = []
    while i < len(messageA) and i < len(ciphertextA):
        xor_msg_ciph.append((messageA[i] ^ ciphertextA[i]))
        i = i + 1
    # XOR the product of @ciphertextA x @messageA and messageB to get result
    i = 0
    ciphertextB_list = []
    while i < len(messageB) and i < len(xor_msg_ciph):
        ciphertextB_list.append(
            (messageB[i] ^ int(xor_msg_ciph[i])).to_bytes(1, "little"))
        i = i + 1
    ciphertextB = b""
    # add it to a string
    for x in ciphertextB_list:
        ciphertextB = ciphertextB + x
    return ciphertextB


def findCiphertext_Test():
    ciphertextA = b"\xef@\x92<$J\xb2\x8c\xbc\xabl'\x016\xd2{W-8\xcas\x83*\xa1\xef)\xc0\xda\x7fe\xab\xb1\x94\x7fJ\x98\xc8\xeei|'t\xb4"
    messageA = b"I'll give you 500 and that's my last offer."
    messageB = b"I'll give you 100 and that's my last offer."

    print("Ciphertext A: ", ciphertextA)
    # XOR ciphertextA and messageA
    i = 0
    xor_msg_ciph = []
    while i < len(messageA) and i < len(ciphertextA):
        xor_msg_ciph.append((messageA[i] ^ ciphertextA[i]))
        i = i + 1
    # XOR the product of @ciphertextA x @messageA and messageB to get result
    i = 0
    ciphertextB_list = []
    while i < len(messageB) and i < len(xor_msg_ciph):
        ciphertextB_list.append(
            (messageB[i] ^ int(xor_msg_ciph[i])).to_bytes(1, "little"))
        i = i + 1
    ciphertextB = b""
    # add it to a string
    for x in ciphertextB_list:
        ciphertextB = ciphertextB + x
    return ciphertextB


if __name__ == "__main__":
    # string = "HELLO WORLD"
    # ct = encryptAffine(string, 1, 1)
    # avalancheCalculator("", "")
    # print("Before encryption: ", string)
    # print("After encryption: ", ct)
    # public_key, derived_key = Diffie_Hellman()
    ciphertextB = findCiphertext_Test()
    print(ciphertextB)
    # print("Encrypted messageB is :", ciphertextB)
