"""Automated tests for the brute-force transposition cipher system."""

import os
import random
import unittest
import tempfile

from transposition_cipher import encrypt_message, decrypt_message
from key_validation import InvalidKeyError, validate_key
from english_detection import load_english_words, is_english
from wp3 import brute_force_decrypt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORD_LIST = os.path.join(BASE_DIR, 'english_words.txt')
TEST_TEXT = os.path.join(BASE_DIR, 'test_wp3_autocase.txt')


class TestTranspositionCipher(unittest.TestCase):
    """Tests for transposition cipher encrypt/decrypt."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypting then decrypting returns original message."""
        msg = "Hello World"
        for key in range(1, len(msg)):
            enc = encrypt_message(key, msg)
            dec = decrypt_message(key, enc)
            self.assertEqual(dec, msg, f"Failed for key={key}")

    def test_key_one_identity(self):
        """Key of 1 returns the original message."""
        msg = "No change expected"
        self.assertEqual(encrypt_message(1, msg), msg)
        self.assertEqual(decrypt_message(1, msg), msg)


class TestKeyValidation(unittest.TestCase):
    """Tests for key validation."""

    def test_valid_key(self):
        """Valid keys should not raise."""
        validate_key(1, 10)
        validate_key(5, 10)
        validate_key(9, 10)

    def test_non_integer_key(self):
        """Non-integer key raises InvalidKeyError."""
        with self.assertRaises(InvalidKeyError):
            validate_key("abc", 10)

    def test_zero_key(self):
        """Key of 0 raises InvalidKeyError."""
        with self.assertRaises(InvalidKeyError):
            validate_key(0, 10)

    def test_negative_key(self):
        """Negative key raises InvalidKeyError."""
        with self.assertRaises(InvalidKeyError):
            validate_key(-1, 10)

    def test_key_too_large(self):
        """Key >= message length raises InvalidKeyError."""
        with self.assertRaises(InvalidKeyError):
            validate_key(10, 10)


class TestEnglishDetection(unittest.TestCase):
    """Tests for English language detection."""

    def setUp(self):
        self.word_set = load_english_words(WORD_LIST)

    def test_english_text(self):
        """Known English text is detected as English."""
        text = "This is a simple test of the English detection module"
        self.assertTrue(is_english(text, self.word_set))

    def test_non_english_text(self):
        """Gibberish is not detected as English."""
        text = "xkcd qwrt plmk zbnv jfgh"
        self.assertFalse(is_english(text, self.word_set))

    def test_empty_text(self):
        """Empty text is not English."""
        self.assertFalse(is_english("", self.word_set))


class TestBruteForce(unittest.TestCase):
    """End-to-end test: encrypt, brute-force, verify."""

    def test_brute_force_recovers_key_and_plaintext(self):
        """Brute-force attack recovers original key and text."""
        with open(TEST_TEXT, 'r', encoding='utf-8') as f:
            original_text = f.read()

        original_key = random.randint(2, 20)
        print(f"\n  Test key chosen: {original_key}")

        ciphertext = encrypt_message(original_key, original_text)

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.txt', delete=False, encoding='utf-8'
        ) as tmp:
            tmp.write(ciphertext)
            tmp_path = tmp.name

        try:
            recovered_key, recovered_text = brute_force_decrypt(
                ciphertext, WORD_LIST
            )
            print(f"  Recovered key: {recovered_key}")
            self.assertEqual(recovered_key, original_key,
                             "Recovered key does not match original.")
            self.assertEqual(recovered_text, original_text,
                             "Recovered plaintext does not match original.")
            print("  PASS: key and plaintext match.")
        finally:
            os.unlink(tmp_path)


if __name__ == '__main__':
    unittest.main()
