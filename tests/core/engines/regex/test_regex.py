import pytest

from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
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
