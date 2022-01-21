# Include any required modules
import collections


def buildTables(rotationNumber):
    alphabet = list(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                     'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'])

    # Create the cipher
    alphabet_list = collections.deque(alphabet)
    alphabet_list.rotate(-rotationNumber)

    # Creating dictionaries
    plainToCipher = {}
    cipherToPlain = {}
    iterator = 0

    for character in alphabet:
        # Create encrypting cipher
        plainToCipher.update({character: alphabet_list[iterator]})
        # Create decrypting cipher
        cipherToPlain.update({alphabet_list[iterator]: character})
        iterator += 1
    return (plainToCipher, cipherToPlain)


def encrypt(plainText, plainToCipher):
    s = ""
    text_arr = plainText.split()
    iterator = 0
    for element in text_arr:
        curr_word = list(element)
        if iterator > 0:
            s = s + " "
        for character in curr_word:
            if character in plainToCipher:
                s = s + plainToCipher.get(character)
            else:
                s = s + character
        iterator += 1
    return s


def decrypt(cipherText, cipherToPlain):
    s = ""
    text_arr = cipherText.split()
    iterator = 0
    for element in text_arr:
        curr_word = list(element)
        if iterator > 0:
            s = s + " "
        for character in curr_word:
            if character in cipherToPlain:
                s = s + cipherToPlain.get(character)
            else:
                s = s + character
        iterator += 1
    return s


# Main
if __name__ == "__main__":
    # 1. Create 2 dictionaries using the buildTables function
    # using a rotation number, e.g. 10
    rotationNumber = 10
    plainToCipher, cipherToPlain = buildTables(rotationNumber)
    # 2. Create a string with a plaintext, e.g. “hello world!”
    ciphertext = 'hello world!'
    # 3. Encrypt the plaintext and print the ciphertext
    ciphertext = encrypt(ciphertext, plainToCipher)
    print(ciphertext)
    print('Encrypted: ' + ciphertext)
    # 4. Decrypt the ciphertext and print the plaintext
    ciphertext = decrypt(ciphertext, cipherToPlain)
    print('Decrypted: ' + ciphertext)
