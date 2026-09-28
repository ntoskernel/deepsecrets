import pytest
from pygments.token import Token as PygmentsToken

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.helpers.token_table import LazyTokens, TokenTable

CONTENT = 'key = "value"\n'


@pytest.fixture()
def table():
    table = TokenTable(File(path='/tmp/t.py', content=CONTENT))
    table.add(PygmentsToken.Name, 'key', 0, 3)
    table.add(PygmentsToken.Operator, '=', 4, 5)
    table.add(PygmentsToken.Literal.String.Double, 'value', 6, 13)  # raw token '"value"', sanitised
    table.add(PygmentsToken.Text.Whitespace, '\n', 13, 14)
    return table


def test_reading_builds_one_token_and_keeps_it(table):
    tokens = LazyTokens(table)
    assert table.built == [None] * 4

    value = tokens[2]
    assert (value.content, value.span, value.type) == (
        'value',
        (7, 12),
        [PygmentsToken.Literal.String.Double, PygmentsToken.Literal.String, PygmentsToken.Literal],
    )
    assert tokens[2] is value and tokens[1:3][1] is value
    assert [t is not None for t in table.built] == [False, False, True, False]


def test_slices_are_views_with_list_bounds(table):
    tokens = LazyTokens(table)
    middle = tokens[1:3]
    assert isinstance(middle, LazyTokens) and len(middle) == 2
    assert [t.content for t in middle] == ['=', 'value']
    assert len(tokens[3:1]) == 0 and len(tokens[-2:]) == 2 and len(tokens[:100]) == 4
    assert [t.content for t in middle[-1:]] == ['value']
    assert [t.content for t in tokens[::2]] == ['key', 'value']


def test_indexes_behave_like_a_list(table):
    tokens = LazyTokens(table)
    assert tokens[-1].content == '\n' and tokens[-4].content == 'key'
    with pytest.raises(IndexError):
        tokens[4]
    with pytest.raises(IndexError):
        tokens[1:3][2]
    assert [t.content for t in tokens] == ['key', '=', 'value', '\n']


def test_existing_tokens_are_kept_as_they_are(table):
    tokens = LazyTokens(table)
    part = tokens[0]
    other = TokenTable(table.file)
    other.add_token(part)
    assert LazyTokens(other)[0] is part
