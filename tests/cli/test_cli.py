import pytest

from deepsecrets.cli import DeepSecretsCliTool, ReturnCodes
from deepsecrets.config import DEFAULT_DEEP_MAX_SIZE
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.utils.exceptions import FileNotFoundException
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
    # regex, regex-candidate scoring, variable scoring and false findings
    assert len(config.rulesets) == 4
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

    assert HashedSecretEngine in config.engines
    assert config.engines.count(RegexEngine) == 1
    assert config.rulesets[HashedSecretsRulesetBuilder] == ['/app/tests/fixtures/hashed_secrets.json']


def test_a_parse_starts_from_a_fresh_config():
    # KI-CLI-12: the config was a process-wide singleton, so what one run set stayed set for the next, masking included
    base = ['', '--target-dir', '/app/tests/fixtures/', '--outfile', '/tmp/x.sarif']
    first = DeepSecretsCliTool(
        args=base
        + ['--disable-masking', '--reflect-findings-in-return-code', '--benchmarking-mode']
        + ['--hashed-values', '/app/tests/fixtures/hashed_secrets.json']
        + ['--excluded-paths', '/app/tests/fixtures/false_findings.json']
    )
    first.parse_arguments()
    second = DeepSecretsCliTool(args=base)
    second.parse_arguments()

    config = second.get_current_config()
    assert config is not first.get_current_config()
    assert config.disable_masking is False
    assert config.return_code_if_findings is False
    assert config._benchmarking_mode is False
    assert HashedSecretsRulesetBuilder not in config.rulesets
    assert not any(path.endswith('false_findings.json') for path in config.global_exclusion_paths)


@pytest.mark.parametrize(
    'extra, bundles_excluded',
    [([], False), (['--skip-bundles'], True), (['--excluded-paths', 'disable', '--skip-bundles'], False)],
)
def test_bundle_exclusions_follow_the_flags(extra, bundles_excluded):
    tool = DeepSecretsCliTool(args=['', '--target-dir', '/app/tests/fixtures/', '--outfile', '/tmp/x.sarif'] + extra)
    tool.parse_arguments()
    config = tool.get_current_config()

    names = [path.rsplit('/', 1)[-1] for path in config.global_exclusion_paths]
    assert ('excluded_bundles.json' in names) is bundles_excluded
    assert ('excluded_paths.json' in names) is ('disable' not in extra)


@pytest.mark.parametrize(
    'extra, detected, ci_mode',
    [([], True, True), ([], False, False), (['--ci'], False, True), (['--no-ci'], True, False)],
)
def test_ci_mode_follows_the_flags_then_the_environment(monkeypatch, extra, detected, ci_mode):
    monkeypatch.setattr('deepsecrets.cli.is_ci_environment', lambda: detected)
    tool = DeepSecretsCliTool(args=['', '--target-dir', '/app/tests/fixtures/', '--outfile', '/tmp/x.sarif'] + extra)
    tool.parse_arguments()
    config = tool.get_current_config()

    assert config.ci_mode is ci_mode


@pytest.mark.parametrize(
    'extra, expected', [([], default_start_method()), (['--multiprocessing-context', 'spawn'], 'spawn')]
)
def test_multiprocessing_context_defaults_to_the_platform_start_method(extra, expected):
    tool = DeepSecretsCliTool(args=['', '--target-dir', '/app/tests/fixtures/', '--outfile', '/tmp/x.sarif'] + extra)
    tool.parse_arguments()
    config = tool.get_current_config()

    assert config.mp_context == expected


@pytest.mark.parametrize('extra, expected', [([], DEFAULT_DEEP_MAX_SIZE), (['--deep-max-size', '0'], 0)])
def test_deep_max_size_flag(extra, expected):
    tool = DeepSecretsCliTool(args=['', '--target-dir', '/app/tests/fixtures/', '--outfile', '/tmp/x.sarif'] + extra)
    tool.parse_arguments()
    config = tool.get_current_config()

    assert config.deep_max_size == expected


def test_the_package_and_the_scanner_carry_the_same_version():
    import tomllib

    from deepsecrets.config import SCANNER_VERSION

    with open('/app/pyproject.toml', 'rb') as f:
        assert tomllib.load(f)['project']['version'] == SCANNER_VERSION


def test_json_output_is_refused_before_the_scan(tmp_path):
    report = tmp_path / 'report.json'
    args = ['', '--target-dir', '/app/tests/fixtures/', '--outfile', str(report), '--outformat', 'json']
    assert DeepSecretsCliTool(args=args).start() == ReturnCodes.ERROR
    assert not report.exists()


def test_hashed_values_without_a_value_disable_the_check():
    # an empty ruleset would still keep the lexer on files over --deep-max-size, for nothing
    tool = DeepSecretsCliTool(
        args=['', '--target-dir', '/app/tests/fixtures/', '--outfile', '/tmp/x.sarif', '--hashed-values']
    )
    tool.parse_arguments()
    assert HashedSecretEngine not in tool.get_current_config().engines


def test_skip_bundles_applies_to_own_exclusion_files_too():
    own = '/app/tests/fixtures/false_findings.json'
    args = ['', '--target-dir', '/app/tests/fixtures/', '--outfile', '/tmp/x.sarif', '--excluded-paths', own, own]
    tool = DeepSecretsCliTool(args=args + ['--skip-bundles'])
    tool.parse_arguments()
    # de-duplicated in order: the first file's patterns are matched first on every run
    names = [path.rsplit('/', 1)[-1] for path in tool.get_current_config().global_exclusion_paths]
    assert names == ['false_findings.json', 'excluded_bundles.json']


def test_a_missing_report_directory_is_refused_before_the_scan(tmp_path):
    tool = DeepSecretsCliTool(
        args=['', '--target-dir', '/app/tests/fixtures/', '--outfile', str(tmp_path / 'no' / 'r.sarif')]
    )
    with pytest.raises(FileNotFoundException, match='does not exist'):
        tool.parse_arguments()
