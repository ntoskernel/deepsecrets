import hashlib
import random
import string

from deepsecrets.core.helpers.naturalness_scorer import naturalness_scorer


def test_bloom_filter_stays_packed():
    # expanding the bits into a list of ints cost 585 ms and 31 MB in every worker
    assert isinstance(naturalness_scorer.bits, bytes)
    assert len(naturalness_scorer.bits) * 8 >= naturalness_scorer.bit_size
    assert not hasattr(naturalness_scorer, 'bit_array')


def test_membership_answers_match_the_unpacked_filter():
    # the answers the list-of-ints filter gave for these words, recorded before it was packed
    rnd = random.Random(11)
    words = [''.join(rnd.choice(string.ascii_lowercase) for _ in range(rnd.randrange(2, 9))) for _ in range(5000)]
    answers = ''.join('1' if naturalness_scorer._in_dictionary(word) else '0' for word in words)

    assert answers.count('1') == 915
    assert hashlib.sha256(answers.encode()).hexdigest() == (
        '1f8bbaf5cb466b5f25b0ad12a596e8def0dfddf3edd52923ecfbf34b1e7b9e03'
    )


def test_scores_of_known_values():
    assert naturalness_scorer.calculate_score('correcthorsebatterystaple') == 1.0
    # a keyboard mash: the dictionary covered it (0.64) until implausible trigrams stopped counting as language
    assert naturalness_scorer.calculate_score('xqzvbnmkjh') == 0.0
    assert naturalness_scorer.calculate_score('kPq9Zr2vXt') == 0.0


def test_random_letters_are_not_language_and_words_still_are():
    import random
    import string

    rng = random.Random(7)
    randoms = [
        ''.join(rng.choice(string.ascii_lowercase) for _ in range(n)) for n in (8, 12, 16, 20, 32) for _ in range(20)
    ]
    words = ['password', 'adminadmin', 'sunshine', 'changeme', 'mysecretpassword', 'letmein', 'iloveyou', 'placeholder']
    # a few short random strings read as pronounceable (4 of these 100, all 8 to 12 letters): a threshold high enough
    # to reject them would start rejecting real words, whose lowest trigram score was 0.40
    assert sum(naturalness_scorer.calculate_score(r) >= 0.6 for r in randoms) <= len(randoms) // 20
    assert all(naturalness_scorer.calculate_score(w) >= 0.6 for w in words)
