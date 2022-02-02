# Include any required modules
import scrypt


def create(salt, password):
    # TODO
    return scrypt.hash(password, salt)


def verify(salt, password, key):
    # TODO
    password = scrypt.hash(password, salt)
    if password == key:
        return True
    else:
        return False

    # and "Invalid password” otherwise.
# Main code to check the functions
if __name__ == "__main__":
    pw = "123456"
    salt = "salt"
    # 1. You should use the create function on a password of your choice
    pw_key = create(salt, pw)
    print(pw_key)
    # and calculate it's key.
    # 2. Ask a user to input a password.
    new_pw = input("Enter new pw: ")
    # 3. Use the verify function to verify the given password against the
    print(verify(salt, new_pw, pw_key))
    # calculate
