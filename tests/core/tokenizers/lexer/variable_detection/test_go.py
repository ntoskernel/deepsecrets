import pytest

from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from tests.case_helpers import variable_detection_case


@pytest.mark.fixture_file_path('1.go')
def test_1(file, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 66


@pytest.mark.fixture_file_path('2.go')
def test_2(file, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 87


@pytest.mark.fixture_file_path('3.go')
def test_3(file, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 2


@pytest.mark.fixture_file_path('4.go')
def test_4(file, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 2


@pytest.mark.fixture_file_path('5.go')
def test_5(file, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 1


@pytest.mark.fixture_file_path('6.go')
def test_6(file, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 4


@pytest.mark.fixture_file_path('7.go')
def test_7(file, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 1
