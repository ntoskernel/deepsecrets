"""The parts of a confidence both evaluators share: the entropy scale and what a random-looking value adds."""


def entropy_score(bits: float) -> float:
    """-1 for a single repeated character, 0 under 3 bits per character, 0 to 35 from 3 to 4 bits, 40 at 4 or more."""
    if bits == 0:
        return -1
    if bits < 3:
        return 0
    if bits < 4:
        return (bits - 3) * 35
    return 40


def randomness_points(score: float, nonsense: float) -> float:
    """Up to 5 confidence points for a random-looking value: its entropy score (entropy_score, 0..40) scaled to 0..5,
    halved for a value that reads as language (nonsense = 1 - naturalness)."""
    return min(max(score, 0), 40) / 40 * 5 * min(nonsense + 0.5, 1)
