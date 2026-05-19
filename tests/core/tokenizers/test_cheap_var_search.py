import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.cheap_var_search import CheapVarSearchTokenizer


@pytest.mark.fixture_file_path('cheap_var_detector_cases.txt')
def test_1(file: File, cheap_var_search_tokenizer: CheapVarSearchTokenizer):
    tokens = cheap_var_search_tokenizer.tokenize(file=file)
    assert len(tokens) == 4
