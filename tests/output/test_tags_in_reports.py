"""Finding tags in a scan's report: test-context from the relative path, --exclude-tags, and SARIF's `tags`. Values are
synthetic."""

import json
from types import SimpleNamespace

import pytest

from deepsecrets.cli import DeepSecretsCliTool, ReturnCodes
from deepsecrets.config import Config
from deepsecrets.core.helpers.finding_tags import PUBLISHABLE, TEST_CONTEXT, WEAK_PASSWORD
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.modes.iscan_mode import ScanMode

TOKEN = 'Tq7XbR2mKp9LvZ4wNc8FjD3sHk3vQ9Zp'


def scan(target, outfile, *extra):
    tool = DeepSecretsCliTool(
        args=['', '--target-dir', str(target), '--outfile', str(outfile), '--process-count', '1', *extra]
    )
    code = tool.start()
    results = json.load(open(outfile))['runs'][0]['results']
    found = {
        (r['locations'][0]['physicalLocation']['artifactLocation']['uri'], r['ruleId']): r['properties']
        for r in results
    }
    return code, found


def test_test_context_follows_the_relative_path(tmp_path):
    # the same file, scanned from its repository and from a parent directory: only the path inside the target counts
    repository = tmp_path / 'tests' / 'repo'
    (repository / 'app').mkdir(parents=True)
    (repository / 'app' / 'settings.py').write_text(f'api_token = "{TOKEN}"\n')

    _, from_repository = scan(repository, tmp_path / 'a.sarif')
    _, from_parent = scan(tmp_path, tmp_path / 'b.sarif')
    assert 'tags' not in from_repository[('app/settings.py', 'S105-VERY-HIGH')]
    assert from_parent[('tests/repo/app/settings.py', 'S105-VERY-HIGH')]['tags'] == [TEST_CONTEXT]


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / 'repo'
    (root / 'app').mkdir(parents=True)
    (root / 'tests').mkdir()
    (root / 'tests' / 'test_client.py').write_text(f'api_token = "{TOKEN}"\n')
    (root / 'app' / 'settings.py').write_text(f'password = "nacc6opq"\napi_token = "{TOKEN[::-1]}"\n')
    return root


def test_sarif_carries_the_tags_and_omits_the_key_when_there_are_none(repository, tmp_path):
    code, found = scan(repository, tmp_path / 'r.sarif')
    assert code == ReturnCodes.OK
    assert found[('tests/test_client.py', 'S105-VERY-HIGH')]['tags'] == [TEST_CONTEXT]
    assert found[('app/settings.py', 'S106-LOW')]['tags'] == [WEAK_PASSWORD]
    assert 'tags' not in found[('app/settings.py', 'S105-VERY-HIGH')]


@pytest.mark.parametrize(
    'excluded, left, code',
    [
        ([], 3, ReturnCodes.FINDINGS_DETECTED),
        ([TEST_CONTEXT], 2, ReturnCodes.FINDINGS_DETECTED),
        ([TEST_CONTEXT, WEAK_PASSWORD], 1, ReturnCodes.FINDINGS_DETECTED),
        ([PUBLISHABLE], 3, ReturnCodes.FINDINGS_DETECTED),
    ],
)
def test_excluded_tags_drop_only_tagged_findings_and_the_exit_code_counts_what_is_left(
    repository, tmp_path, excluded, left, code
):
    extra = ['--reflect-findings-in-return-code'] + (['--exclude-tags', *excluded] if excluded else [])
    returned, found = scan(repository, tmp_path / 'r.sarif', *extra)
    assert (returned, len(found)) == (code, left)
    assert not any(set(excluded) & set(properties.get('tags', [])) for properties in found.values())


def test_the_exit_code_is_ok_when_every_finding_is_excluded(tmp_path):
    (tmp_path / 'repo' / 'tests').mkdir(parents=True)
    (tmp_path / 'repo' / 'tests' / 'test_client.py').write_text(f'api_token = "{TOKEN}"\n')
    args = ('--reflect-findings-in-return-code', '--exclude-tags', TEST_CONTEXT)
    assert scan(tmp_path / 'repo', tmp_path / 'r.sarif', *args) == (ReturnCodes.OK, {})
    assert scan(tmp_path / 'repo', tmp_path / 'r.sarif', *args[:1])[0] == ReturnCodes.FINDINGS_DETECTED


def test_an_unknown_tag_is_refused(capsys):
    tool = DeepSecretsCliTool(
        args=['', '--target-dir', 'tests/fixtures', '--outfile', '/tmp/x.sarif', '--exclude-tags', 'near-miss']
    )
    with pytest.raises(SystemExit) as exit:
        tool.parse_arguments()
    assert exit.value.code == 2 and '--exclude-tags' in capsys.readouterr().err


def test_the_flag_sets_the_excluded_tags():
    args = ['', '--target-dir', 'tests/fixtures', '--outfile', '/tmp/x.sarif']
    tool = DeepSecretsCliTool(args=[*args, '--exclude-tags', TEST_CONTEXT, PUBLISHABLE, TEST_CONTEXT])
    tool.parse_arguments()
    assert tool.get_current_config().excluded_tags == [TEST_CONTEXT, PUBLISHABLE]
    tool = DeepSecretsCliTool(args=args)
    tool.parse_arguments()
    assert tool.get_current_config().excluded_tags == []


def test_the_tag_filter():
    findings = [
        Finding(detection='a', start_offset=0, end_offset=1, rules=[Rule(id='S105')], tags=[TEST_CONTEXT]),
        Finding(detection='b', start_offset=2, end_offset=3, rules=[Rule(id='S106')], tags=[WEAK_PASSWORD]),
        Finding(detection='c', start_offset=4, end_offset=5, rules=[Rule(id='S36')]),
    ]
    config = Config()
    mode = SimpleNamespace(config=config)
    assert ScanMode.filter_by_tags(mode, findings) == findings
    config.set_excluded_tags([WEAK_PASSWORD, PUBLISHABLE])
    assert [f.detection for f in ScanMode.filter_by_tags(mode, findings)] == ['a', 'c']
