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
