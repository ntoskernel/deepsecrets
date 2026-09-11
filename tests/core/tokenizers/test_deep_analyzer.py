import json
import random

from deepsecrets.core.model.file import File
from deepsecrets.core.model.semantic import Variable
from deepsecrets.core.tokenizers.helpers.semantic.deep_analyzer import DeepAnalyzer
from deepsecrets.core.tokenizers.lexer import LexerTokenizer


def _variable(start: int, end: int) -> Variable:
    var = Variable()
    var.span = [start, end]
    return var


def test_suppression_index_matches_linear_scan():
    rnd = random.Random(9)
    analyzer = DeepAnalyzer(regions=[], post_filter=True)
    for _ in range(200):
        # overlapping, unsorted, touching and nested regions, as several suppression rules produce
        regions = []
        for _ in range(rnd.randrange(0, 12)):
            start = rnd.randrange(0, 60)
            regions.append([start, start + rnd.randrange(0, 20)])
        is_suppressed = analyzer._suppression_index(regions)

        for _ in range(50):
            start = rnd.randrange(-2, 80)
            var = _variable(start, start + rnd.randrange(0, 10))
            assert is_suppressed(var) == analyzer._if_suppressed(var, regions), (regions, var.span)


def test_suppression_index_edges():
    analyzer = DeepAnalyzer(regions=[], post_filter=True)
    is_suppressed = analyzer._suppression_index([[10, 20], [5, 8]])

    assert is_suppressed(_variable(10, 20)) is True  # boundaries are inclusive
    assert is_suppressed(_variable(5, 8)) is True
    assert is_suppressed(_variable(9, 12)) is False  # starts before the covering region
    assert is_suppressed(_variable(12, 21)) is False  # ends after it
    assert is_suppressed(_variable(0, 1)) is False
    assert analyzer._suppression_index([])(_variable(0, 1)) is False


def test_flat_json_values_stay_suppressed():
    # the case the index was built for: thousands of variables against thousands of suppression regions
    content = json.dumps({f'key_{i:05}': f'value{i:08}xyz' for i in range(3000)}, indent=2)
    tokens = LexerTokenizer(deep_token_inspection=True).tokenize(File(path='/tmp/flat.json', content=content))
    assert tokens == []
