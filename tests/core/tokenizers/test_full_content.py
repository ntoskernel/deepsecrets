import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer


@pytest.mark.fixture_file_path('1.toml')
def test_full_content(file: File, full_content_tokenizer: FullContentTokenizer):
    tokens = full_content_tokenizer.tokenize(file=file)
    assert len(tokens) == 1
    assert tokens[0].content == file.content
