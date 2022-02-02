from hashlib import sha256
import time


def mine(block_number, transactions, previous_hash, difficulty):
    new_hash = ""
    prefix_str = '0' * difficulty
    nonce = 0

    while not new_hash.startswith(prefix_str):
        text = str(block_number) + transactions + \
            previous_hash + str(nonce)

        text = text.encode("ascii")
        new_hash = str(sha256(text).hexdigest())
        nonce = nonce + 1
    return new_hash


if __name__ == "__main__":

    transactions = '''
    Me->Yanko->30,
    Yanko->Tedo->45
    '''
    difficulty = 7

    start = time.time()
    hi = mine(5, transactions,
              "0000b9015ce2a08b61216ba5a0778545bf4ddd7ceb7bbd85dd8062b29a9140bf", difficulty)
    print(hi)
    total_time = time.time() - start
    print("Took " + str(total_time) + " sec.")
