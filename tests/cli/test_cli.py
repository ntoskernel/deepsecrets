import pytest

from deepsecrets.cli import DeepSecretsCliTool
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder


@pytest.fixture(scope='module')
def args_1():
    return [
        '',
        '--target-dir',
        '/app/tests/fixtures/',
        '--false-findings',
        '/app/tests/fixtures/false_findings.json',
        '--outfile',
        './fdsafad.json',
        '--max-file-size',
        '500',
        '--verbose',
        '--reflect-findings-in-return-code',
    ]


@pytest.fixture(scope='module')
def args_2():
    return [
        '',
        '--target-dir',
        '/app/tests/fixtures/',
        '--false-findings',
        '/app/tests/fixtures/false_findings.json',
        '--excluded-paths',
        'built-in',
        '/app/tests/fixtures/false_findings.json',
        '--outfile',
        './fdsafad.json',
        '--outformat',
        'dojo-sarif',
    ]


def test_1_cli(args_1):
    tool = DeepSecretsCliTool(args=args_1)
    tool.parse_arguments()

    config = tool.get_current_config()

    assert config is not None
    assert len(config.rulesets) == 3
    assert len(config.engines) == 2
    assert len(config.global_exclusion_paths) == 1

    assert config.max_file_size == 500
    assert config.output.path == './fdsafad.json'
    assert config.workdir_path == '/app/tests/fixtures'
    assert config.output.type == 'sarif'  # Starting release 2.0

    return_code = tool.start()
    assert return_code != 0


def test_2_cli(args_2):
    tool = DeepSecretsCliTool(args=args_2)
    tool.parse_arguments()

    config = tool.get_current_config()

    assert config is not None
    assert len(config.global_exclusion_paths) == 2
    assert config.max_file_size == 0
    assert config.output.type == 'dojo-sarif'


def test_hashed_values_registers_hashed_engine():
    tool = DeepSecretsCliTool(
        args=[
            '',
            '--target-dir',
            '/app/tests/fixtures',
            '--hashed-values',
            'tests/fixtures/hashed_secrets.json',
            '--outfile',
            './fdsafad.json',
        ]
    )
    tool.parse_arguments()
    config = tool.get_current_config()

    try:
        assert HashedSecretEngine in config.engines
        assert config.engines.count(RegexEngine) == 1
        assert config.rulesets[HashedSecretsRulesetBuilder] == ['/app/tests/fixtures/hashed_secrets.json']
    finally:
        # the config singleton outlives this test (KI-CLI-12)
        config.rulesets.pop(HashedSecretsRulesetBuilder, None)
