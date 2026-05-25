import pytest

from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from tests.case_helpers import variable_detection_case


@pytest.mark.fixture_file_path('1.rb')
def test_1(file, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 3
