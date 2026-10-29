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
    # 22 key-value pairs, and the --connect and --warehouse-dir options of a sqoop command (the command-option detector)
    assert len(variables) == 24 + 2


MINIFIED = 'if(a<b.length)x=1;App.DROPBOX_APPKEY="q3kz8m2x7vw1r5t";App.MODE=">"'


@pytest.mark.parametrize('lexed, found', [(True, True), (False, False)])
def test_the_tag_skip_depends_on_the_tier(lexed, found):
    # where the lexer also reads the file a tag is skipped only when it is one; above the tier the wide skip stays, on
    # purpose (KI-TOK-36), so `a<b` hides everything up to the next '>'
    tokenizer = CheapVarSearchTokenizer(lexed=lexed)
    tokens = tokenizer.tokenize(File(path='/tmp/app.min.js', relative_path='app.min.js', content=MINIFIED))
    assert ('DROPBOX_APPKEY' in [token.semantic.payload.name for token in tokens]) is found


def test_command_options_and_dotnet_settings_are_variables():
    content = (
        'mvn sonar:sonar -Dsonar.login=5f2b9c1e8a7d4036b1e9f0c2a4d6e8b0c1d3e5f7 -U\n'
        'tool --api-key "Zk3pQ9rT2mX7vB1n" --verbose\n'
        '<add key="loginradius:apisecret" value="3f9a1c2e-7b4d-4e8a-9c1f-2d3e4f5a6b7c"/>\n'
    )
    tokens = CheapVarSearchTokenizer().tokenize(File(path='/tmp/build.sh', relative_path='build.sh', content=content))
    names = {token.semantic.payload.name: token.content for token in tokens}
    assert names['sonar.login'].startswith('5f2b9c1e') and names['api-key'] == 'Zk3pQ9rT2mX7vB1n'
    assert names['loginradius:apisecret'].startswith('3f9a1c2e')


def test_a_reused_tokenizer_returns_only_the_current_files_tokens(tmp_path):
    first, second = tmp_path / 'a.txt', tmp_path / 'b.txt'
    first.write_text('password = "hunter22hunter22"\n')
    second.write_text('nothing to see here\n')
    tokenizer = CheapVarSearchTokenizer(lexed=True)
    assert tokenizer.tokenize(File(path=str(first)))
    assert tokenizer.tokenize(File(path=str(second))) == []


DEFINES = (
    '#include <stdio.h>\n'
    '#define FLICKR_KEY "Hk3vQ9ZpL2mXw7RtYb4NcF8aZk3pQ9rT"\n'
    '  #  define API_SECRET @"Tq7XbR2mKp9LvZ4wNc8F"\n'
    '#define SHORT "abc12"\n'
    '#define WITH_QUOTE "abc"def"\n'
    'int x = 1; #define NOT_AT_LINE_START "Zk3pQ9rT2mX7vB1n"\n'
    '#define NUMBER 42\n'
)


@pytest.mark.parametrize('lexed', [True, False])
def test_a_define_is_a_variable(lexed):
    # 2.3 (R4): the lexer reads a #define line as a comment, so only the cheap search sees the constant
    tokens = CheapVarSearchTokenizer(lexed=lexed).tokenize(
        File(path='/tmp/keys.h', relative_path='keys.h', content=DEFINES)
    )
    pairs = {(t.semantic.payload.name, t.content) for t in tokens}
    assert ('FLICKR_KEY', 'Hk3vQ9ZpL2mXw7RtYb4NcF8aZk3pQ9rT') in pairs
    assert ('API_SECRET', 'Tq7XbR2mKp9LvZ4wNc8F') in pairs  # Objective-C's @"..."
    assert not {name for name, _ in pairs} & {'SHORT', 'WITH_QUOTE', 'NOT_AT_LINE_START', 'NUMBER'}


def test_a_define_is_reported_once_scanned(tmp_path):
    from tests.case_helpers import semantic_case_with_cheap_var_search

    path = tmp_path / 'keys.m'
    path.write_text(DEFINES)
    findings, _, _ = semantic_case_with_cheap_var_search(File(path=str(path), relative_path='keys.m'))
    assert {f.internal_score['var'] for f in findings} == {'FLICKR_KEY', 'API_SECRET'}
