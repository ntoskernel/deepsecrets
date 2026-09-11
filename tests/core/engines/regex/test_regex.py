import pytest

from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.regex import RegexRule
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from tests.case_helpers import regex_case


@pytest.mark.fixture_file_path('regex_checks.txt')
def test_1(file: File, regex_engine: RegexEngine):
    findings, _, _ = regex_case(
        tokenizer=FullContentTokenizer(),
        engine=regex_engine,
        file=file,
    )

    assert len(findings) == 13
    assert findings[0].final_rule.id == 'S0'
    assert findings[1].final_rule.id == 'S0'
    assert findings[2].final_rule.id == 'S1'
    assert findings[3].final_rule.id == 'S2'
    assert findings[4].final_rule.id == 'S3'
    assert findings[5].final_rule.id == 'S4'
    assert findings[6].final_rule.id == 'S5'

    assert findings[7].final_rule.id == 'S19'
    assert findings[7].detection == 'sneakypass'

    assert findings[8].final_rule.id == 'S19'
    assert findings[8].detection == 'ridCNWnbTpavfVuJvWmS'


@pytest.mark.fixture_file_path('extless/radius')
def test_extless(file: File, regex_engine: RegexEngine):
    findings, tokens, variables = regex_case(
        tokenizer=FullContentTokenizer(),
        engine=regex_engine,
        file=file,
    )

    assert len(findings) == 1
    assert findings[0].rules[0].id == 'S28'


@pytest.mark.fixture_file_path('7.go')
def test_go_7(file: File, regex_engine: RegexEngine):
    findings, tokens, variables = regex_case(
        tokenizer=FullContentTokenizer(),
        engine=regex_engine,
        file=file,
    )

    assert len(findings) == 0


@pytest.mark.fixture_file_path('cases/private_keys.txt')
def test_private_keys(file: File, regex_engine: RegexEngine):
    findings, tokens, variables = regex_case(
        tokenizer=FullContentTokenizer(),
        engine=regex_engine,
        file=file,
    )

    assert len(findings) == 2


def _token(content: str) -> Token:
    return Token(file=File(path=None, content=content + '\n'), content=content, span=[0, len(content)])


def test_rule_match_honours_negative_pattern_and_case():
    rule = RegexRule(id='T1', name='test', pattern='secret_[a-z]+', negative_pattern='example')

    assert rule.match(_token('SECRET_abc and secret_def')) == [(0, 10), (15, 25)]
    assert rule.match(_token('secret_abc example')) == []


def test_rule_match_reports_decoded_content_as_whole_token():
    rule = RegexRule(id='T1', name='test', pattern='secret_[a-z]+', case_sensitive=True)
    token = _token('c2VjcmV0X2FiYw==')
    token.uncovered_content.append('secret_abc')

    assert rule.match(token) == [(0, len(token.content))]
    assert rule.match('SECRET_abc') == []
