"""English language detection module using a dictionary word list."""

import string


def load_english_words(filepath):
    """Load English words from a file into a set.

    Args:
        filepath: Path to a text file with one word per line.

    Returns:
        A set of lowercase English words.
    """
    words = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            word = line.strip().lower()
            if word:
                words.add(word)
    return words


def is_english(text, word_set, threshold=0.5):
    """Determine whether the given text is likely English.

    Tokenizes the text by spaces, strips punctuation from each
    token, and checks what fraction of tokens appear in the
    word set.

    Args:
        text: The text to check.
        word_set: A set of known English words (lowercase).
        threshold: Minimum fraction of recognized words to
            consider the text English (default 0.5).

    Returns:
        True if the fraction of recognized words meets the
        threshold, False otherwise.
    """
    text = text.lower()
    text = text.replace('_', ' ')
    tokens = text.split()

    if not tokens:
        return False

    punct_table = str.maketrans('', '', string.punctuation)
    match_count = 0
    total_count = 0

    for token in tokens:
        cleaned = token.translate(punct_table)
        if not cleaned:
            continue
        total_count += 1
        if cleaned in word_set:
            match_count += 1

    if total_count == 0:
        return False

    return (match_count / total_count) >= threshold
