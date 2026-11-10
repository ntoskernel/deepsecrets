import pytest

from deepsecrets.core.engines.semantic import could_be_chosen_password, variable_rule
from deepsecrets.core.helpers.variable_evaluator import EvaluationResult
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
    assert findings[0].rules[0].name == 'High Entropy and Variable Naming'
    assert findings[1].rules[0].name == 'High Entropy and Variable Naming'


@pytest.mark.fixture_file_path('1.toml')
def test_toml_1(file: File):
    findings, tokens, variables = semantic_case(file)
    assert len(tokens) == 51

    assert tokens[50].semantic.type == SemanticType.VARIABLE
    assert tokens[50].semantic.name == 'MATTERMOST_BOT_TOKEN'

    assert len(findings) == 2
    assert findings[0].rules[0].name == 'High Entropy and Variable Naming'
    assert findings[1].rules[0].name == 'High Entropy and Variable Naming'


@pytest.mark.fixture_file_path('2.toml')
def test_toml_2(file: File):
    findings, tokens, _ = semantic_case(file)
    assert len(tokens) == 13
    # SERVICE_OAUTH, STT_KEY and TTS_KEY repeat one 8-character block (3.0 bits): too low in entropy for a key or
    # token name, so no S106
    assert [f.internal_score['var'] for f in findings] == ['S3_SECRET']


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
    findings, tokens, vars = semantic_case(file)
    assert len(findings) == 1


@pytest.mark.fixture_file_path('cheap_var_detector_cases.txt')
def test_with_cheap_var_search(file: File):
    findings, tokens, vars = semantic_case_with_cheap_var_search(file)
    # 12 until 2.3 dropped S106's letters-only values: `andOnceAgainPassword` holds a plain run of letters
    assert len(findings) == 11


@pytest.mark.fixture_file_path('5.py')
def test_5(file: File):
    findings, tokens, vars = semantic_case(file)
    assert len(findings) == 3


@pytest.mark.fixture_file_path('1.php')
def test_6_php(file: File):
    findings, tokens, vars = semantic_case(file)
    # 2 until 2.3: the S106 `password` value is a plain run of letters
    assert len(findings) == 1


@pytest.mark.fixture_file_path('1.txt')
def test_ini_in_txt(file: File):
    findings, tokens, vars = semantic_case(file)
    # the sectionless ini probe lexes the file and finds the variable; its value, `adminadmin`, is letters alone, a
    # default S106 no longer reports (2.3)
    assert 'password' in [t.semantic.name for t in vars if t.semantic is not None]
    assert findings == []


def test_low_entropy_values_are_reported_only_under_names_people_choose(tmp_path):
    path = tmp_path / 'settings.py'
    path.write_text(
        'password = "nacc6opq"\n'
        'db_pass = "nacc6opq"\n'
        'client_secret = "nacc6opq"\n'
        'api_key = "nacc6opq"\n'
        'auth_token = "nacc6opq"\n'
        'STT_KEY = "vhpn6mbsvhpn6mbs"\n'
        'refresh_token = "Hk3vQ9ZpL2mXw7Rt"\n'
    )
    findings, _, _ = semantic_case(File(path=str(path), relative_path='settings.py'))
    assert sorted((f.internal_score['var'], f.final_rule.id) for f in findings) == [
        ('client_secret', 'S106'),
        ('db_pass', 'S106'),
        ('password', 'S106'),
        ('refresh_token', 'S105'),
    ]


def test_s106_stays_in_the_low_tier(tmp_path):
    from deepsecrets.config import TIER_FLOORS, WEAK_VALUE_MAX_CONFIDENCE

    assert WEAK_VALUE_MAX_CONFIDENCE == TIER_FLOORS['medium'] - 1 == 4
    path = tmp_path / 'settings.py'
    path.write_text(
        'password = "sunshine"\n'  # a dictionary word, letters alone: not reported
        'db_password = "nacc6opq"\n'  # 2.75 bits under a strong name: 7, HIGH, before the cap
        'refresh_token = "Hk3vQ9ZpL2mXw7Rt"\n'  # S105 is not capped
    )
    findings, _, _ = semantic_case(File(path=str(path), relative_path='settings.py'))
    reported = {f.internal_score['var']: f for f in findings}
    assert 'password' not in reported
    assert (reported['db_password'].final_rule.id, reported['db_password'].final_rule.confidence) == ('S106', 4)
    assert reported['refresh_token'].final_rule.id == 'S105' and reported['refresh_token'].final_rule.confidence > 4
    # the cap is the engine's: the evaluator, and so the tracer's evaluation record, keeps the naming confidence
    assert reported['db_password'].internal_score['conf'] == 7


@pytest.mark.parametrize(
    'value, chosen',
    [
        ('Summer2019', True),
        ('"p@ss-w0rd"', True),
        ('qwe!rty', True),
        ('changeme', False),  # letters alone: a default
        ('Password', False),
        ('admin1', False),  # 6 characters
        ("'1234'", False),
        ('', False),
    ],
)
def test_s106_reports_only_a_value_someone_may_have_chosen(value, chosen):
    assert could_be_chosen_password(value) is chosen
    weak = EvaluationResult(is_dangerous=True, entropy_score=0, export_confidence=4, allows_low_entropy=True)
    rule = variable_rule(weak, value)
    assert (rule.id if rule else None) == ('S106' if chosen else None)


def test_the_s106_value_check_leaves_s105_alone():
    random = EvaluationResult(is_dangerous=True, entropy_score=2.5, export_confidence=7)
    assert variable_rule(random, 'abcdef').id == 'S105'
