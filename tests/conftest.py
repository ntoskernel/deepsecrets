import pytest

from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.rulesets.variable_scoring import VariableScoringRulesetBuilder
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.tokenizers.per_line import PerLineTokenizer
from deepsecrets.core.utils.fs import get_path_inside_package


def pytest_configure(config):
    config.addinivalue_line('markers', "fixture_file_path: pass file path to retrieve a File object")


@pytest.fixture
def hashed_secrets_fixture_file_location():
    return 'tests/fixtures/hashed_secrets.json'


@pytest.fixture
def regex_ruleset_location():
    return 'rules/regexes.json'


@pytest.fixture
def variable_scoring_ruleset_location():
    return 'rules/variable_scoring_rules.json'


@pytest.fixture
def file(request):
    # Get the marker named 'load_file' from the test
    marker = request.node.get_closest_marker('fixture_file_path')
    if marker is None:
        return None

    file_path = f'tests/fixtures/{marker.args[0]}'
    return File(path=file_path, relative_path=file_path)


@pytest.fixture
def variable_scoring_rules(variable_scoring_ruleset_location):
    builder = VariableScoringRulesetBuilder()
    builder.with_rules_from_file(get_path_inside_package(variable_scoring_ruleset_location))
    return builder.rules


@pytest.fixture
def hashed_secrets_engine(hashed_secrets_fixture_file_location):
    builder = HashedSecretsRulesetBuilder()
    builder.with_rules_from_file(hashed_secrets_fixture_file_location)
    return HashedSecretEngine(ruleset=builder.rules)


@pytest.fixture
def regex_engine(regex_ruleset_location):
    builder = RegexRulesetBuilder()
    builder.with_rules_from_file(get_path_inside_package(regex_ruleset_location))
    return RegexEngine(ruleset=builder.rules)


@pytest.fixture
def lexer_tokenizer():
    yield LexerTokenizer(deep_token_inspection=True)


@pytest.fixture
def full_content_tokenizer():
    yield FullContentTokenizer()


@pytest.fixture
def per_line_tokenizer():
    yield PerLineTokenizer()
