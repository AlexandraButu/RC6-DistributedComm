import unittest
from rc6 import RC6

class TestRC6(unittest.TestCase):
    def setUp(self):
        self.rc6 = RC6()
        self.r = 20

    def prepare_keys(self, hex_values):
        return self.rc6.key_schedule(hex_values[:], len(hex_values), self.r)

    # Verificare criptare/decriptare cand cheia si textul sunt zero
    def test1(self):
        L = [0x00000000] * 4
        keys = self.prepare_keys(L)
        plaintext = [0x00000000] * 4
        print("Test1 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test1 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test1 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)

    # Test cu cheie personalizata si bloc specific de text 
    def test2(self):
        L = [0x11223344, 0xaabbccdd, 0x55667788, 0x99aabbcc]
        keys = self.prepare_keys(L)
        plaintext = [0x13572468, 0x24681357, 0xdeadbeef, 0xcafebabe]
        print("Test2 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test2 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test2 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)

    # Criptare/decriptare cu cheie de 6 cuvinte, toti zero
    def test3(self):
        L = [0x00000000] * 6
        keys = self.prepare_keys(L)
        plaintext = [0x00000000] * 4
        print("Test3 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test3 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test3 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)

    # Cheie 6 cuvinte non-zero, bloc de text modificat
    def test4(self):
        L = [0x12345678, 0xabcdef12, 0x13579bdf, 0x2468ace0, 0xfeedface, 0x0badf00d]
        keys = self.prepare_keys(L)
        plaintext = [0x11111111, 0x22222222, 0x33333333, 0x44444444]
        print("Test4 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test4 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test4 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)

    # Cheie lunga 8 cuvinte zero, text clar zero
    def test5(self):
        L = [0x00000000] * 8
        keys = self.prepare_keys(L)
        plaintext = [0x00000000] * 4
        print("Test5 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test5 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test5 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)

    # Cheie lunga 8 cuvinte diverse, text complex
    def test6(self):
        L = [0xdeadbeef, 0x12345678, 0xaabbccdd, 0x0f0f0f0f, 0x01020304, 0x05060708, 0x99887766, 0xabcdef01]
        keys = self.prepare_keys(L)
        plaintext = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff]
        print("Test6 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test6 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test6 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)

    # ASCII string 'Test' ca intregi + afisari
    def test7(self):
        L = [0x12345678, 0x9abcdef0, 0x11111111, 0x22222222]
        keys = self.prepare_keys(L)
        plaintext = [84, 101, 115, 116]  # 'Test'
        print("Test7 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test7 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test7 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)

    # Test stringuri simple 
    def test8_strings(self):
        L = [0x00000000] * 4
        keys = self.prepare_keys(L)
        samples = ["Test123", "RC6Cipher", "", "  "]
        for s in samples:
            encrypted = self.rc6.encrypt(s, keys, self.r)
            decrypted = self.rc6.decrypt(encrypted, keys, self.r)
            print(f"Original: '{s}' -> Encrypted: '{encrypted}' -> Decrypted: '{decrypted}'")
            self.assertEqual(s, decrypted)

    # Conversie hex -> int mare
    def test9_big_integer(self):
        hex_string = "1abcdeffedcba12345"
        big_integer = int(hex_string, 16)
        print(f"Test9 - Big integer: {big_integer}")
        self.assertIsInstance(big_integer, int)

  # Criptare/decriptare cu simboluri ASCII
    def test10_ascii_symbols(self):
        L = [0x1a2b3c4d, 0x5e6f7081, 0x9a0b1c2d, 0x3e4f5061]
        keys = self.prepare_keys(L)
        plaintext = [33, 64, 35, 36]  # '!@#$'
        print("Test10 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test10 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test10 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)

    # Cifre ca text ('1234')
    def test11_numeric_text(self):
        L = [0x0f1e2d3c, 0x4b5a6978, 0x8796a5b4, 0xc3d2e1f0]
        keys = self.prepare_keys(L)
        plaintext = [49, 50, 51, 52]  # '1234'
        print("Test11 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test11 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test11 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)

    # 'ABCD'
    def test12_abcd_combo(self):
        L = [0xa1a2a3a4, 0xb1b2b3b4, 0xc1c2c3c4, 0xd1d2d3d4]
        keys = self.prepare_keys(L)
        plaintext = [65, 66, 67, 68]  # 'ABCD'
        print("Test12 - Before encryption:", plaintext)
        ciphertext = self.rc6.encrypt_unsigned_integer(plaintext[:], keys, self.r)
        print("Test12 - After encryption:", ciphertext)
        decrypted = self.rc6.decrypt_unsigned_integer(ciphertext[:], keys, self.r)
        print("Test12 - After decryption:", decrypted)
        self.assertEqual(decrypted, plaintext)
if __name__ == '__main__':
    unittest.main()
