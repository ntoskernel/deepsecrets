import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from tests.case_helpers import variable_detection_case


@pytest.fixture(scope='module')
def file_php_1():
    path = 'tests/fixtures/1.php'
    return File(path=path, relative_path=path)


@pytest.mark.fixture_file_path('1.php')
def test_1(file: File, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 12
