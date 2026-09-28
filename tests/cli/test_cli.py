import pytest

from deepsecrets.cli import DeepSecretsCliTool
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.utils.multiprocessing_setup import default_start_method


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


@pytest.mark.parametrize(
    'extra, detected, ci_mode',
    [([], True, True), ([], False, False), (['--ci'], False, True), (['--no-ci'], True, False)],
)
def test_ci_mode_follows_the_flags_then_the_environment(monkeypatch, extra, detected, ci_mode):
    monkeypatch.setattr('deepsecrets.cli.is_ci_environment', lambda: detected)
    tool = DeepSecretsCliTool(args=['', '--target-dir', '/app/tests/fixtures/', '--outfile', '/tmp/x.sarif'] + extra)
    config = tool.get_current_config()
    monkeypatch.setattr(config, 'ci_mode', not ci_mode)  # the singleton keeps what earlier tests set
    tool.parse_arguments()

    assert config.ci_mode is ci_mode


@pytest.mark.parametrize(
    'extra, expected', [([], default_start_method()), (['--multiprocessing-context', 'spawn'], 'spawn')]
)
def test_multiprocessing_context_defaults_to_the_platform_start_method(monkeypatch, extra, expected):
    tool = DeepSecretsCliTool(args=['', '--target-dir', '/app/tests/fixtures/', '--outfile', '/tmp/x.sarif'] + extra)
    config = tool.get_current_config()
    monkeypatch.setattr(config, 'mp_context', 'fork')
    tool.parse_arguments()

    assert config.mp_context == expected
