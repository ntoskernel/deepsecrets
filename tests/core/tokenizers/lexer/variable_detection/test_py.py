import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from tests.case_helpers import variable_detection_case


@pytest.mark.fixture_file_path('1.py')
def test_1(file: File, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 5


@pytest.mark.fixture_file_path('2.py')
def test_2(file: File, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 93


@pytest.mark.fixture_file_path('3.py')
def test_3(file: File, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 3
    assert variables[1].semantic.name == 'password'
    assert variables[1].content == 'TESTSECRET1234'

    assert variables[2].semantic.name == 'pwd'
    assert variables[2].content == '2TESTSECRET1234'


@pytest.mark.fixture_file_path('4.py')
def test_4(file: File, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 11


@pytest.mark.fixture_file_path('5.py')
def test_5(file: File, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 5
