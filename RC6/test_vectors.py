import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from RC6.rc6 import RC6


def hex_string_to_words(hex_string):
    bytes_data = bytes.fromhex(hex_string.replace(" ", ""))
    return [int.from_bytes(bytes_data[i:i+4], byteorder="little") for i in range(0, len(bytes_data), 4)]

def test_vector(name, plaintext_hex, key_hex, expected_cipher_hex):
    rc6 = RC6()
    plaintext = hex_string_to_words(plaintext_hex)
    key_words = hex_string_to_words(key_hex)
    expected_cipher = hex_string_to_words(expected_cipher_hex)

    expanded_key = rc6.key_schedule(key_words, len(key_words), rc6.r)
    encrypted = rc6.encrypt_unsigned_integer(plaintext, expanded_key, rc6.r)

    match = encrypted == expected_cipher
    print(f"\n{name}")
    print(f"Plaintext : {plaintext}")
    print(f"Expected  : {expected_cipher}")
    print(f"Encrypted : {encrypted}")
    print(f"Match     : {'DA' if match else 'NU'}")

    return match

if __name__ == "__main__":
    test_vector("Test vector 1",
        plaintext_hex="00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        key_hex="00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        expected_cipher_hex="8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 98 48 a4 1e"
    )

    test_vector("Test vector 2",
        plaintext_hex="02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1",
        key_hex="01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78",
        expected_cipher_hex="52 4e 19 2f 47 15 c6 23 1f 51 f6 36 7e a4 3f 18"
    )

    test_vector("Test vector 3",
        plaintext_hex="00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        key_hex="00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0000 00 00 00 00 00 00 00",
        expected_cipher_hex="6c d6 1b cb 19 0b 30 38 4e 8a 3f 16 86 90 ae 82"
    )

    test_vector("Test vector 4",
        plaintext_hex="02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1",
        key_hex="01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78 89 9a ab bc cd de ef f0",
        expected_cipher_hex="68 83 29 d0 19 e5 05 04 1e 52 e9 2a f9 52 91 d4"
    )

    test_vector("Test vector 5",
        plaintext_hex="00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        key_hex="00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        expected_cipher_hex="8f 5f bd 05 10 d1 5f a8 93 fa 3f da 6e 85 7e c2"
    )

    test_vector("Test vector 6",
        plaintext_hex="02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1",
        key_hex="01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78 89 9a ab bc cd de ef f0 10 32 54 76 98 ba dc fe",
        expected_cipher_hex="c8 24 18 16 f0 d7 e4 89 20 ad 16 a1 67 4e 5d 48"
    )
