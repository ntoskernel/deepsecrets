import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from tests.case_helpers import variable_detection_case


@pytest.mark.fixture_file_path('3.js')
def test_1(file: File, lexer_tokenizer: LexerTokenizer):
    variables, lexer, _ = variable_detection_case(lexer_tokenizer, file)
    assert lexer.name == 'JSX'
    assert len(variables) == 2


@pytest.mark.fixture_file_path('1.jsx')
def test_2_jsx(file: File, lexer_tokenizer: LexerTokenizer):
    variables, lexer, _ = variable_detection_case(lexer_tokenizer, file)
    assert lexer.name == 'JSX'
    assert len(variables) == 1


@pytest.mark.fixture_file_path('2.jsx')
def test_3_jsx(file: File, lexer_tokenizer: LexerTokenizer):
    variables, lexer, _ = variable_detection_case(lexer_tokenizer, file)
    assert lexer.name == 'JSX'
    assert len(variables) == 0


@pytest.mark.fixture_file_path('3.jsx')
def test_4_jsx(file: File, lexer_tokenizer: LexerTokenizer):
    variables, lexer, _ = variable_detection_case(lexer_tokenizer, file, post_filter=False)
    assert lexer.name == 'JSX'
    assert len(variables) == 0


@pytest.mark.fixture_file_path('4.js')
def test_5_js(file: File, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 0


@pytest.mark.fixture_file_path('cases/tricky_secrets.min.js')
def test_6_minjs_5_1(file, lexer_tokenizer):
    tokens = lexer_tokenizer.tokenize(file, post_filter=True)
    variables = lexer_tokenizer.get_variables(tokens)
    assert len(variables) == 27


@pytest.mark.fixture_file_path('5.js')
def test_7_js(file: File, lexer_tokenizer: LexerTokenizer):
    variables, _, tokens = variable_detection_case(lexer_tokenizer, file, post_filter=False)
    assert len(variables) == 5
