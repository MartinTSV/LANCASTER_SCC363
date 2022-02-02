# Include any required modules
import hashlib


# Get the hexdigest and bin_value of a string.
def HexBinSHA256(stringToConvert):

    binValue = ' '.join(format(ord(x), '08b') for x in stringToConvert)
    stringToConvert = stringToConvert.encode()
    hexValue = hashlib.sha256(stringToConvert).hexdigest()
    return (hexValue, binValue)

# Function for bruteforcing a sha256 hexdigest of a 5-char word.


def bruteForce(hexdigest):
    alphabet = list("abcdefghijklmnopqrstuvwxyz")
    f = open("bruteforce_list.txt", "r")

    for line in f:
        word = line
        line = list(line)
        #Filter /n
        line = [x.replace('\n', '') for x in line if x != '\n']
        new = ""

        # Convert list to string
        for x in line:
            new += x

        #Hexdigest and compare
        line = new
        line = line.encode()
        line = hashlib.sha256(line).hexdigest()
        if line == hexdigest:
            return word

    print("Word doesn't exist in the list.\n")


if __name__ == "__main__":

    # String
    string = "polka"
    # Call function
    hex_value, binary_value = HexBinSHA256(string)
    # Print
    print("String: ", string)
    print("Hex value: ", hex_value)
    print("Binary value: ", binary_value)

    # Decode string
    print("\nBruteforcing...")
    word = bruteForce(hex_value)
    if word != None:
        print("Decoded: ", word)
