import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import SemanticType
from tests.case_helpers import semantic_case, semantic_case_with_cheap_var_search


@pytest.mark.fixture_file_path('4.py')
def test_python_1(file: File):
    findings, tokens, variables = semantic_case(file)
    assert len(tokens) == 13

    assert tokens[3].semantic.type == SemanticType.VARIABLE
    assert tokens[3].semantic.name == 'pass'

    assert len(findings) == 0


@pytest.mark.fixture_file_path('2.json')
def test_json_2(file: File):
    findings, tokens, variables = semantic_case(file)
    assert len(tokens) == 6

    assert tokens[0].semantic.type == SemanticType.VARIABLE
    assert tokens[0].semantic.name == 'access_Token'

    assert tokens[1].semantic.type == SemanticType.VARIABLE
    assert tokens[1].semantic.name == 'accessToken'

    assert len(findings) == 2
    assert findings[0].rules[0].name == 'Entropy+Var naming'
    assert findings[1].rules[0].name == 'Entropy+Var naming'


@pytest.mark.fixture_file_path('1.toml')
def test_toml_1(file: File):
    findings, tokens, variables = semantic_case(file)
    assert len(tokens) == 51

    assert tokens[50].semantic.type == SemanticType.VARIABLE
    assert tokens[50].semantic.name == 'MATTERMOST_BOT_TOKEN'

    assert len(findings) == 2
    assert findings[0].rules[0].name == 'Entropy+Var naming'
    assert findings[1].rules[0].name == 'Entropy+Var naming'


@pytest.mark.fixture_file_path('2.toml')
def test_toml_2(file: File):
    findings, tokens, _ = semantic_case(file)
    assert len(tokens) == 13
    assert len(findings) == 4


@pytest.mark.fixture_file_path('2.sh')
def test_sh_2(file: File):
    findings, tokens, _ = semantic_case(file)
    assert len(tokens) == 16
    assert len(findings) == 1
    assert findings[0].final_rule.name == 'Dangerous condition'


@pytest.mark.fixture_file_path('1.html')
def test_html_1(file: File):
    findings, _, _ = semantic_case(file)
    assert len(findings) == 0


@pytest.mark.fixture_file_path('cases/tricky_secrets.min.js')
def test_minjs_5_1(file: File):
    findings, tokens, vars = semantic_case(file)
    assert len(findings) == 5


@pytest.mark.fixture_file_path('3.html')
def test_html_3(file: File):
    findings, _, _ = semantic_case(file)
    assert len(findings) == 1


@pytest.mark.fixture_file_path('cases/code_in_markdown.md')
def test_ec_code_in_markdown(file: File):
    findings, tokens, vars = semantic_case(file)
    assert len(findings) == 1


@pytest.mark.fixture_file_path('8.go')
def test_go_8(file: File):
    findings, tokens, vars = semantic_case(file)
    assert len(findings) == 1


@pytest.mark.fixture_file_path('1.go')
def test_go_1(file: File):
    findings, tokens, vars = semantic_case(file)
    assert len(findings) == 1


@pytest.mark.fixture_file_path('3.conf')
def test_conf_3(file: File):
    # TODO: HOCON
    findings, tokens, vars = semantic_case(file)
    assert len(findings) == 1


@pytest.mark.fixture_file_path('cheap_var_detector_cases.txt')
def test_with_cheap_var_search(file: File):
    findings, tokens, vars = semantic_case_with_cheap_var_search(file)
    assert len(findings) == 2


@pytest.mark.fixture_file_path('5.py')
def test_5(file: File):
    findings, tokens, vars = semantic_case(file)
    assert len(findings) == 1
