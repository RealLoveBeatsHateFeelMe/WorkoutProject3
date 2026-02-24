"""Transposition cipher encryption and decryption module."""

import math


def encrypt_message(key, message):
    """Encrypt a message using a transposition cipher with the given key.

    The message characters are distributed across 'key' columns
    in round-robin fashion, then columns are concatenated to form
    the ciphertext.

    Args:
        key: A positive integer used as the number of columns.
        message: The plaintext string to encrypt.

    Returns:
        The encrypted ciphertext string.
    """
    ciphertext = [''] * key
    for index, char in enumerate(message):
        column = index % key
        ciphertext[column] += char
    return ''.join(ciphertext)


def decrypt_message(key, message):
    """Decrypt a message that was encrypted with a transposition cipher.

    This reverses the encryption process by calculating the number
    of rows and distributing ciphertext characters back into the
    correct positions.

    Args:
        key: A positive integer used as the number of columns.
        message: The ciphertext string to decrypt.

    Returns:
        The decrypted plaintext string.
    """
    num_columns = key
    num_rows = math.ceil(len(message) / num_columns)
    num_full_columns = len(message) % num_columns
    if num_full_columns == 0:
        num_full_columns = num_columns

    plaintext = [''] * len(message)
    col_start = 0
    for col in range(num_columns):
        if col < num_full_columns:
            col_len = num_rows
        else:
            col_len = num_rows - 1
        for row in range(col_len):
            plaintext[row * num_columns + col] = message[col_start + row]
        col_start += col_len

    return ''.join(plaintext)
