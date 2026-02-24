Brute-Force Attack on Transposition Cipher
===========================================

This program performs a brute-force attack on text encrypted with a
columnar transposition cipher. Given a ciphertext file, it automatically
tries every possible integer key from 1 up to the length of the ciphertext,
decrypts the message with each candidate key, and uses an English language
detection module to determine whether the decrypted output is valid English.
When a matching key is found the recovered plaintext and key are written to
the specified output files.

Usage:
    python wp3.py <ciphertext_file> <plaintext_file> <key_file>

Example:
    python wp3.py message_enc.txt recovered_plaintext.txt recovered_key.txt

The project is organized into four Python modules. transposition_cipher.py
contains the encrypt and decrypt functions. key_validation.py provides
custom exception classes (InvalidKeyError, InputFileNotFoundError) and a
key validation function. english_detection.py loads a word list from
english_words.txt and checks whether a piece of text is likely English by
measuring the fraction of recognized words. wp3.py is the main driver that
reads command-line arguments, orchestrates the brute-force search using the
Python multiprocessing module to distribute key attempts across all
available CPU cores, and writes the results. Automated tests are provided
in test_wp3.py.
