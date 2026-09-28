"""`LexerTokenizer` builds `Token` objects lazily; its output must equal the eager loop it replaced, token by token."""

import glob
import os
from typing import List, Type

import pytest
import regex as re
from pygments.token import Token as PygmentsToken

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers import subfile_regions_helper
from deepsecrets.core.tokenizers.helpers.semantic.deep_analyzer import DeepAnalyzer
from deepsecrets.core.tokenizers.helpers.semantic.language import Language
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.detector import Match, RegionDetector
from deepsecrets.core.tokenizers.helpers.subfile_regions_helper import SubFileRegionsHelper
from deepsecrets.core.tokenizers.helpers.token_table import TokenTable
from deepsecrets.core.tokenizers.helpers.type_stream import token_to_typestream_item
from deepsecrets.core.tokenizers.lexer import LexerTokenizer

SHELL = "curl -u admin\ncurl -u 'login01:password01' -s https://x\nsort -u f.txt\ncurl -u 'u:p' -s x\n"
CURL_CREDENTIALS_DETECTOR = RegionDetector(
    stream_pattern=re.compile('(L)(L)$'),
    match_rules={1: Match(values=[re.compile('^-u$')])},
    match_semantics={},
)


def curl_argstring_breakdown(so_far_tokens, so_far_type_stream, current_token):
    """`SingleTokenImprover._curl_argstring_breakdown` as of 2.1.1, the only improvement (shell only)."""
    tail_length = min(2, len(so_far_tokens))
    tail_tokens = so_far_tokens[len(so_far_tokens) - tail_length :]
    projected_tail = so_far_type_stream[len(so_far_type_stream) - tail_length :]
    projected_tail += token_to_typestream_item(current_token)
    if not CURL_CREDENTIALS_DETECTOR.match(tail_tokens, projected_tail):
        return [current_token]
    new_parts = current_token.content.split(':')
    if new_parts[0] == '' or new_parts[1] == '':
        return [current_token]
    final = []
    for part in new_parts:
        t = Token(
            file=current_token.file,
            content=part,
            span=current_token.file.get_span_for_string(part, between=current_token.span),
        )
        t.set_type([PygmentsToken.Text])
        final.append(t)
    return final


class EagerLexerTokenizer(LexerTokenizer):
    """`LexerTokenizer.tokenize` as it was before tokens were built lazily: one `Token` per lexer token."""

    def _get_types_for_token(self, token) -> List[Type]:
        types = [token]
        if token.parent is not None:
            if token.parent == PygmentsToken:
                return types
            types.extend(self._get_types_for_token(token.parent))
        return types

    def tokenize(self, file: File, post_filter=True) -> List[Token]:
        self.regions = set()
        self.token_stream = ''
        self.lexer = self._find_lexer_for_file(file)
        if not self.lexer:
            return self.tokens
        try:
            self.language = Language.from_text(self.lexer.filenames[0])
        except (ValueError, IndexError):
            self.language = Language.from_text(file.extension)
        except Exception:
            pass

        raw_tokens = list(self.lexer.get_tokens_unprocessed(file.content))
        current_position = 0
        for _, types, content in raw_tokens:
            types = self._get_types_for_token(types)
            start = current_position
            end = start + len(content)
            current_position = end
            if current_position > file.length:
                continue
            try:
                if PygmentsToken.Error in types and len(types) == 1:
                    continue
                content = self.sanitize(content)
                if not content:
                    continue
                span = file.get_span_for_string(content, between=[start - 1, end + 1])
                token = Token(file=file, content=content, span=span)
                token.set_type(types)
                improved_tokens = [token]
                if self.language == Language.SHELL:
                    improved_tokens = curl_argstring_breakdown(self.tokens, self.token_stream, token)
                self.tokens.extend(improved_tokens)
                for improved in improved_tokens:
                    self.token_stream += token_to_typestream_item(token=improved)
            except Exception as e:
                str(e)

        self.regions = SubFileRegionsHelper(
            file=file, language=self.language, tokens=self.tokens, stream=self.token_stream
        ).find()
        deep_analyzer = DeepAnalyzer(
            regions=self.regions, deep_inspection=self.settings.deep_token_inspection, post_filter=post_filter
        )
        self.tokens = deep_analyzer.get_final_tokens()
        self.silent_regions = deep_analyzer.silent_regions
        return self.tokens


def _signature(tokenizer: LexerTokenizer, tokens: List[Token]):
    out = []
    for t in tokens:
        semantic = None
        if t.semantic is not None:
            var = t.semantic.payload
            semantic = (
                t.semantic.type.name,
                t.semantic.creds_probability,
                None if var.name_token is None else (var.name_token.content, tuple(var.name_token.span)),
                var.value_token is t,
                tuple(var.span),
                id(var.found_by),
            )
        out.append((t.content, tuple(t.span) if t.span else None, tuple(str(x) for x in t.type), semantic))
    regions = sorted((r.substitute_start_index, r.substitute_end_index, str(r.language)) for r in tokenizer.regions)
    return out, tokenizer.token_stream, regions, tokenizer.silent_regions


def _files():
    # problem_files/ exists only on developer machines, so it is left out to keep the test the same everywhere
    paths = sorted(p for p in glob.glob('tests/fixtures/**/*', recursive=True) if '/problem_files/' not in p)
    return [File(path=p) for p in paths if os.path.isfile(p)] + [File(path='/tmp/curl.sh', content=SHELL)]


def _both(file, monkeypatch, **settings):
    post_filter = settings.pop('post_filter')
    lazy = LexerTokenizer(**settings)
    lazy_result = _signature(lazy, lazy.tokenize(file, post_filter=post_filter))
    with monkeypatch.context() as m:
        # sub-file regions (code blocks in Markdown, YAML block scalars) are re-lexed by a nested tokenizer
        m.setattr(subfile_regions_helper, 'LexerTokenizer', EagerLexerTokenizer)
        eager = EagerLexerTokenizer(**settings)
        eager_result = _signature(eager, eager.tokenize(file, post_filter=post_filter))
    return lazy_result, eager_result


def test_every_fixture_tokenizes_as_before(monkeypatch):
    files = _files()
    assert len(files) > 80
    for file in files:
        lazy, eager = _both(file, monkeypatch, deep_token_inspection=True, post_filter=True)
        assert lazy == eager, file.path


@pytest.mark.parametrize('deep, post_filter', [(True, False), (False, False)])
def test_unfiltered_settings_tokenize_as_before(monkeypatch, deep, post_filter):
    # what the diagnostics tracer and the sub-file re-lex use; the files with sub-file regions or an improver
    for file in _files():
        if not file.path.endswith(('.md', '.yaml', '.yml', '.sh')):
            continue
        lazy, eager = _both(file, monkeypatch, deep_token_inspection=deep, post_filter=post_filter)
        assert lazy == eager, file.path


def test_most_tokens_are_never_built(monkeypatch):
    tables = []
    record = TokenTable.__init__

    def capture(self, file):
        record(self, file)
        tables.append(self)

    monkeypatch.setattr(TokenTable, '__init__', capture)
    final = LexerTokenizer(deep_token_inspection=True).tokenize(File(path='tests/fixtures/2.py'))

    [table] = tables
    built = sum(token is not None for token in table.built)
    # every kept token is built; the rows cleanup drops by type alone are not, except where detection read them
    assert len(final) <= built < len(table) / 2
