import secrets
import string


def generate_password(length=16):

    characters = (
        string.ascii_letters
        + string.digits
        + string.punctuation
    )

    password = ""

    for _ in range(length):
        password += secrets.choice(characters)

    return password