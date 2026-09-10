import pytest
from deepsecrets.core.utils.guess_filetype import FileTypeGuesser


@pytest.mark.parametrize(
    'content',
    [
        'token=12312312345645456\npassword=adminadmin',
        '# comment\n\n; another comment\nKEY = value\nspring.datasource.password=abc\nEMPTY=\n',
        '[auth]\nlogin = cchecker\npassword = fbyuihqwjlkfr\n',
    ],
)
def test_ini_detected(content: str):
    assert FileTypeGuesser().guess(name='file', content=content, extension='txt') == 'ini'


@pytest.mark.parametrize(
    'content, expected',
    [
        ('host: localhost\npassword: passowrd\n', 'yaml'),
        ('password = "quoted"\n', 'toml'),
    ],
)
def test_other_formats_keep_their_guess(content: str, expected: str):
    assert FileTypeGuesser().guess(name='file', content=content, extension='txt') == expected


@pytest.mark.parametrize(
    'content',
    [
        'Some prose here.\nx=y\nand some more prose\n',
        'export FOO=bar\n',
    ],
)
def test_partial_key_value_content_is_not_ini(content: str):
    assert FileTypeGuesser().guess(name='file', content=content, extension='txt') != 'ini'
