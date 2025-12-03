import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers import PerLineTokenizer


@pytest.mark.fixture_file_path('1.toml')
def test_per_line(file: File, per_line_tokenizer: PerLineTokenizer):
    tokens = per_line_tokenizer.tokenize(file=file)
    assert len(tokens) == 76
