"""Brute-force attack on transposition cipher using multiprocessing."""

import sys
import os
import multiprocessing

from transposition_cipher import decrypt_message
from key_validation import InvalidKeyError, InputFileNotFoundError
from english_detection import load_english_words, english_score

WORD_LIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'english_words.txt')

SCORE_THRESHOLD = 0.5


def _try_keys(args):
    """Worker function that evaluates a range of keys.

    Returns the best (highest-scoring) key from this chunk,
    or None if no key exceeds the threshold.

    Args:
        args: Tuple of (key_range, ciphertext, word_list_path).

    Returns:
        Tuple (score, key, plaintext) for the best candidate,
        or None if nothing scored above the threshold.
    """
    key_range, ciphertext, word_list_path = args
    word_set = load_english_words(word_list_path)

    best = None
    for key in key_range:
        try:
            plaintext = decrypt_message(key, ciphertext)
            score = english_score(plaintext, word_set)
            if score >= SCORE_THRESHOLD:
                if best is None or score > best[0]:
                    best = (score, key, plaintext)
        except Exception:
            continue
    return best


def brute_force_decrypt(ciphertext, word_list_path=None):
    """Attempt all possible keys to decrypt a transposition cipher.

    Uses multiprocessing to distribute key attempts across
    available CPU cores.  Each worker returns the best key from
    its chunk; the overall best is selected from all workers.

    Args:
        ciphertext: The encrypted text to break.
        word_list_path: Path to the English word list file.

    Returns:
        Tuple (key, plaintext) on success.

    Raises:
        InvalidKeyError: If no valid key is found.
    """
    if word_list_path is None:
        word_list_path = WORD_LIST_PATH

    msg_len = len(ciphertext)
    if msg_len < 2:
        raise InvalidKeyError("Ciphertext is too short to brute-force.")

    max_key = msg_len - 1
    num_workers = multiprocessing.cpu_count()

    all_keys = list(range(1, max_key + 1))
    chunk_size = max(1, len(all_keys) // num_workers)
    chunks = []
    for i in range(0, len(all_keys), chunk_size):
        chunks.append(all_keys[i:i + chunk_size])

    tasks = [(chunk, ciphertext, word_list_path) for chunk in chunks]

    with multiprocessing.Pool(processes=num_workers) as pool:
        results = pool.map(_try_keys, tasks)

    best = None
    for result in results:
        if result is not None:
            if best is None or result[0] > best[0]:
                best = result

    if best is not None:
        return (best[1], best[2])

    raise InvalidKeyError(
        "Brute-force failed: no key produced valid English text."
    )


def main():
    """Main entry point for the brute-force attack program.

    Reads command-line arguments, performs the attack, and writes
    the recovered plaintext and key to output files.
    """
    if len(sys.argv) != 4:
        print("Usage: python wp3.py <ciphertext_file> "
              "<plaintext_file> <key_file>")
        sys.exit(1)

    ciphertext_file = sys.argv[1]
    plaintext_file = sys.argv[2]
    key_file = sys.argv[3]

    if not os.path.isfile(ciphertext_file):
        raise InputFileNotFoundError(
            f"Input file not found: {ciphertext_file}"
        )

    try:
        with open(ciphertext_file, 'r', encoding='utf-8') as f:
            ciphertext = f.read()
    except OSError as e:
        raise InputFileNotFoundError(
            f"Cannot read input file: {e}"
        ) from e

    if not ciphertext.strip():
        print("Error: ciphertext file is empty.")
        sys.exit(1)

    print(f"Ciphertext length: {len(ciphertext)}")
    print(f"Trying keys 1 to {len(ciphertext) - 1} "
          f"using {multiprocessing.cpu_count()} processes...")

    key, plaintext = brute_force_decrypt(ciphertext)

    print(f"Key found: {key}")
    print(f"Plaintext preview: {plaintext[:80]}...")

    with open(plaintext_file, 'w', encoding='utf-8') as f:
        f.write(plaintext)

    with open(key_file, 'w', encoding='utf-8') as f:
        f.write(str(key))

    print(f"Recovered plaintext written to {plaintext_file}")
    print(f"Recovered key written to {key_file}")


if __name__ == "__main__":
    main()
