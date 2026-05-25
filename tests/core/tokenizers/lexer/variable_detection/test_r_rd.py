import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from tests.case_helpers import variable_detection_case


@pytest.mark.fixture_file_path(
    'problem_files/dmpe-rbitly_5e7b14925d70ccc7f59a05e4b5a398c4acce6e76_man-link_Metrics_EncodersByCount.Rd'
)
@pytest.mark.skip()
def test_1(file: File, lexer_tokenizer: LexerTokenizer):
    variables, _, _ = variable_detection_case(lexer_tokenizer, file)
    assert len(variables) == 1
