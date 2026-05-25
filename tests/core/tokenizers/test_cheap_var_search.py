import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.cheap_var_search import CheapVarSearchTokenizer


@pytest.mark.fixture_file_path('cheap_var_detector_cases.txt')
def test_1(file: File, cheap_var_search_tokenizer: CheapVarSearchTokenizer):
    _ = cheap_var_search_tokenizer.tokenize(file=file)
    variables = cheap_var_search_tokenizer.get_variables()
    assert len(variables) == 15


@pytest.mark.fixture_file_path('6.json')
def test_2(file: File, cheap_var_search_tokenizer: CheapVarSearchTokenizer):
    _ = cheap_var_search_tokenizer.tokenize(file=file)
    variables = cheap_var_search_tokenizer.get_variables()
    assert len(variables) == 24
