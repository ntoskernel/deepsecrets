import pytest
from deepsecrets.core.model.file import File
from deepsecrets.core.utils.lexer_finder import LexerFinder


@pytest.mark.fixture_file_path('extless/json')
def test_extless_json(file: File):
    lexer = LexerFinder().find(file)
    assert lexer.name == 'JSON'


@pytest.mark.fixture_file_path('extless/ini')
def test_extless_ini(file: File):
    lexer = LexerFinder().find(file)
    assert lexer.name == 'INI'


@pytest.mark.fixture_file_path('extless/yaml')
def test_extless_yaml(file: File):
    lexer = LexerFinder().find(file)
    assert lexer.name == 'YAML'


@pytest.mark.fixture_file_path('3.js')
def test_js_react(file: File):
    lexer = LexerFinder().find(file)
    assert lexer.name == 'JSX'
