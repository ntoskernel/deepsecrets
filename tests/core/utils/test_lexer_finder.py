import pytest
from deepsecrets.core.model.file import File
from deepsecrets.core.utils.lexer_finder import LexerFinder


@pytest.fixture(scope='module')
def file_extless_json():
    path = 'tests/fixtures/extless/json'
    return File(path=path, relative_path=path)

@pytest.fixture(scope='module')
def file_extless_yaml():
    path = 'tests/fixtures/extless/yaml'
    return File(path=path, relative_path=path)

@pytest.fixture(scope='module')
def file_extless_ini():
    path = 'tests/fixtures/extless/ini'
    return File(path=path, relative_path=path)

@pytest.fixture(scope='module')
def file_js_react():
    path = 'tests/fixtures/3.js'
    return File(path=path, relative_path=path)



def test_extless_json(file_extless_json):
    lf = LexerFinder()
    lexer = lf.find(file_extless_json)

    assert lexer.name == 'JSON'

def test_extless_ini(file_extless_ini):
    lf = LexerFinder()
    lexer = lf.find(file_extless_ini)

    assert lexer.name == 'INI'


def test_extless_yaml(file_extless_yaml):
    lf = LexerFinder()
    lexer = lf.find(file_extless_yaml)

    assert lexer.name == 'YAML'

def test_js_react(file_js_react):
    lf = LexerFinder()
    lexer = lf.find(file_js_react)

    assert lexer.name == 'JSX'