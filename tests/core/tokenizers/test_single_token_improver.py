import glob

import pytest
import regex as re

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers import single_token_improver as sti
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.detector import Match, RegionDetector
from deepsecrets.core.tokenizers.helpers.type_stream import token_to_typestream_item
from deepsecrets.core.tokenizers.lexer import LexerTokenizer

SHELL = "curl -u admin\ncurl -u 'login01:password01' -s https://x\nsort -u f.txt\ncurl -u 'u:p' -s x\n"


def _full_stream_reference(self, so_far_tokens, so_far_type_stream, current_token):
    # the implementation before the tail check: the detector ran over the whole stream for every token
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
        token = Token(
            file=current_token.file,
            content=part,
            span=current_token.file.get_span_for_string(part, between=current_token.span),
        )
        token.set_type([sti.PygmentsToken.Text])
        final.append(token)
    return final


def _snapshot(file: File):
    tokens = LexerTokenizer(deep_token_inspection=True).tokenize(file)
    return [
        (t.content, tuple(t.span) if t.span else None, str(t.type[:1]), getattr(t.semantic, 'creds_probability', None))
        for t in tokens
    ]


def _shell_files():
    fixtures = [p for p in glob.glob('tests/fixtures/**/*', recursive=True) if p.endswith(('.sh', '.md'))]
    return [File(path=p) for p in fixtures] + [File(path='/tmp/curl.sh', content=SHELL)]


def test_tail_check_matches_full_stream_reference(monkeypatch):
    for file in _shell_files():
        current = _snapshot(file)
        with monkeypatch.context() as m:
            m.setattr(sti.SingleTokenImprover, '_curl_argstring_breakdown', _full_stream_reference)
            reference = _snapshot(file)
        assert current == reference, file.path


def test_curl_credentials_still_split():
    tokens = LexerTokenizer(deep_token_inspection=True).tokenize(File(path='/tmp/curl.sh', content=SHELL))
    by_content = {t.content: t for t in tokens}

    # the user part becomes the variable name (removed by the post-filter), the password its value
    assert "'login01:password01'" not in by_content
    assert by_content['password01'].semantic.creds_probability == 9
    assert SHELL[slice(*by_content['password01'].span)] == 'password01'


def test_detector_sees_constant_sized_input(monkeypatch):
    # matching the whole stream per token made shell tokenization quadratic in file length
    seen = []
    original = sti.CURL_CREDENTIALS_DETECTOR.__class__.match

    def spy(self, tokens, stream):
        seen.append((len(tokens), len(stream)))
        return original(self, tokens, stream)

    monkeypatch.setattr(sti.CURL_CREDENTIALS_DETECTOR.__class__, 'match', spy)
    content = ''.join(f'echo "step {i}" && export VAR_{i}=value{i}\n' for i in range(300))
    LexerTokenizer(deep_token_inspection=True).tokenize(File(path='/tmp/long.sh', content=content))

    assert len(seen) > 1000
    assert max(tokens for tokens, _ in seen) <= 2
    assert max(stream for _, stream in seen) <= 3


@pytest.mark.parametrize('prefix_tokens', [0, 1, 2, 5])
def test_short_prefixes(prefix_tokens):
    file = File(path='/tmp/x.sh', content='curl -u a:b\n')
    improver = sti.SingleTokenImprover(sti.Language.SHELL)
    so_far = [Token(file=file, content='-u', span=[5, 7]) for _ in range(prefix_tokens)]
    for token in so_far:
        token.set_type([sti.PygmentsToken.Text])
    current = Token(file=file, content='a:b', span=[8, 11])
    current.set_type([sti.PygmentsToken.Text])

    result = improver._curl_argstring_breakdown(so_far, 'L' * prefix_tokens, current)
    reference = _full_stream_reference(improver, so_far, 'L' * prefix_tokens, current)

    assert [t.content for t in result] == [t.content for t in reference]
