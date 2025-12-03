import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from tests.case_helpers import variable_detection_case


@pytest.fixture(scope='module')
def file_js_3():
    path = 'tests/fixtures/3.js'
    return File(path=path, relative_path=path)


@pytest.fixture(scope='module')
def file_jsx_1():
    path = 'tests/fixtures/1.jsx'
    return File(path=path, relative_path=path)


@pytest.fixture(scope='module')
def file_jsx_2():
    path = 'tests/fixtures/2.jsx'
    return File(path=path, relative_path=path)


@pytest.fixture(scope='module')
def file_jsx_3():
    path = 'tests/fixtures/3.jsx'
    return File(path=path, relative_path=path)


@pytest.fixture(scope='module')
def file_js_4():
    path = 'tests/fixtures/4.js'
    return File(path=path, relative_path=path)


@pytest.fixture(scope='module')
def file_minjs_5_1():
    path = 'tests/fixtures/5_1.min.js'
    return File(path=path, relative_path=path)


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


@pytest.mark.fixture_file_path('5_1.min.js')
def test_minjs_5_1(file, lexer_tokenizer):
    tokens = lexer_tokenizer.tokenize(file, post_filter=True)
    variables = lexer_tokenizer.get_variables(tokens)
    assert len(variables) == 17
