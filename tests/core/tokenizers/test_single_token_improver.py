import random

import pytest
import regex as re
from pygments.token import Token as PygmentsToken

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers import single_token_improver as sti
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.detector import Match, RegionDetector
from deepsecrets.core.tokenizers.helpers.type_stream import stream_item, token_to_typestream_item
from deepsecrets.core.tokenizers.lexer import LexerTokenizer

SHELL = "curl -u admin\ncurl -u 'login01:password01' -s https://x\nsort -u f.txt\ncurl -u 'u:p' -s x\n"
TEXT, NEWLINE, OPERATOR = PygmentsToken.Text, PygmentsToken.Text.Whitespace, PygmentsToken.Operator


def _full_stream_reference(so_far_tokens, so_far_type_stream, current_token):
    # the rule as first written: the stream regex over everything emitted so far, for every token
    projected = so_far_type_stream + token_to_typestream_item(current_token)
    rule = RegionDetector(
        stream_pattern=re.compile('(L)(L)$'),
        match_rules={1: Match(values=[re.compile('^-u$')])},
        match_semantics={},
    )
    if not rule.match(so_far_tokens, projected):
        return [current_token]
    parts = current_token.content.split(':')
    if parts[0] == '' or parts[1] == '':
        return [current_token]
    final = []
    for part in parts:
        token = Token(file=current_token.file, content=part, span=[0, 0])
        token.set_type([PygmentsToken.Text])
        final.append(token)
    return final


def _emit_with_reference(sequence):
    file = File(path='/tmp/r.sh', content='x')
    tokens, stream = [], ''
    for ttype, content in sequence:
        token = Token(file=file, content=content, span=[0, 0])
        token.set_type([ttype])
        try:
            parts = _full_stream_reference(tokens, stream, token)
        except IndexError:
            continue  # the tokenizer skipped a token whose improvement raised
        tokens.extend(parts)
        stream += ''.join(token_to_typestream_item(t) for t in parts)
    return [(t.content, item) for t, item in zip(tokens, stream)]


def _emit_with_improver(sequence):
    improver = sti.SingleTokenImprover(sti.Language.SHELL)
    contents, stream = [], []
    for ttype, content in sequence:
        item = stream_item(ttype, content)
        parts = improver.improve(ttype, content, item, ''.join(stream[-2:]), contents[-2:])
        for part, part_type in [(content, ttype)] if parts is None else parts:
            contents.append(part)
            stream.append(stream_item(part_type, part))
    return list(zip(contents, stream))


def test_same_decisions_as_the_whole_stream_rule():
    words = [(TEXT, '-u'), (TEXT, 'admin'), (TEXT, 'a:b'), (TEXT, ':b'), (TEXT, 'a:'), (TEXT, 'a:b:c')]
    other = [(NEWLINE, '\n'), (OPERATOR, '='), (PygmentsToken.Keyword, 'if')]
    rnd = random.Random(7)
    for _ in range(3000):
        sequence = [rnd.choice(words * 2 + other) for _ in range(rnd.randrange(1, 9))]
        assert _emit_with_improver(sequence) == _emit_with_reference(sequence), sequence


@pytest.mark.parametrize(
    'previous_items, previous_contents, content, item, expected',
    [
        ('L', ['-u'], 'login:password', 'L', [('login', TEXT), ('password', TEXT)]),
        ('uL', ['if', '-u'], 'a:b:c', 'L', [('a', TEXT), ('b', TEXT), ('c', TEXT)]),
        ('L', ['-u'], ':password', 'L', None),
        ('L', ['-u'], 'login:', 'L', None),
        ('', [], 'a:b', 'L', None),
        ('o', ['-u'], 'a:b', 'L', None),
        ('L', ['-x'], 'a:b', 'L', None),
        ('L', ['-u'], '=', 'o', None),
        # today's behaviour, probably unintended: no ':' after `-u` drops the token
        ('L', ['-u'], 'admin', 'L', []),
        # and the stream regex's `$` matched before a final newline, so a newline two tokens after `-u` is dropped
        ('LL', ['-u', 'login:'], '\n', '\n', []),
        ('LL', ['x', '-u'], '\n', '\n', None),
    ],
)
def test_curl_credentials_cases(previous_items, previous_contents, content, item, expected):
    improver = sti.SingleTokenImprover(sti.Language.SHELL)
    assert improver.improve(TEXT, content, item, previous_items, previous_contents) == expected


def test_curl_credentials_still_split():
    tokens = LexerTokenizer(deep_token_inspection=True).tokenize(File(path='/tmp/curl.sh', content=SHELL))
    by_content = {t.content: t for t in tokens}

    # the user part becomes the variable name (removed by the post-filter), the password its value
    assert "'login01:password01'" not in by_content
    assert by_content['password01'].semantic.creds_probability == 9
    assert SHELL[slice(*by_content['password01'].span)] == 'password01'


def test_improver_sees_only_the_two_previous_tokens(monkeypatch):
    # matching the whole stream per token made shell tokenization quadratic in file length
    seen = []
    original = sti.SingleTokenImprover.improve

    def spy(self, ttype, content, item, previous_items, previous_contents):
        seen.append((len(previous_items), len(previous_contents)))
        return original(self, ttype, content, item, previous_items, previous_contents)

    monkeypatch.setattr(sti.SingleTokenImprover, 'improve', spy)
    content = ''.join(f'echo "step {i}" && export VAR_{i}=value{i}\n' for i in range(300))
    LexerTokenizer(deep_token_inspection=True).tokenize(File(path='/tmp/long.sh', content=content))

    assert len(seen) > 1000
    assert max(max(pair) for pair in seen) <= 2


def test_only_shell_is_improved():
    assert sti.SingleTokenImprover(sti.Language.SHELL).applies()
    assert not sti.SingleTokenImprover(sti.Language.PYTHON).applies()
    assert not sti.SingleTokenImprover(None).applies()
