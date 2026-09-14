import json

import pytest

from deepsecrets.cli import DeepSecretsCliTool
from deepsecrets.config import config
from deepsecrets.core.utils.log import clear_error_list, get_error_list, logger


@pytest.fixture()
def target(tmp_path):
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src' / 'settings.py').write_text('password = "T7r$kq92LmZx"\n')
    (tmp_path / 'node_modules' / 'pkg').mkdir(parents=True)
    (tmp_path / 'node_modules' / 'pkg' / 'index.js').write_text(
        'api_key = "q8Lk3VzP0mXw7Rt2Yb9NcF4sHd6JgA1eUo5KiM3T"\n'
    )
    return tmp_path


def scan(target, outfile, *extra):
    # the config singleton outlives other tests' runs; benchmarking mode would skip writing the report
    config._set_benchmarking_mode(False)
    config.set_oneshot_path(None)
    tool = DeepSecretsCliTool(
        args=['', '--target-dir', str(target), '--outfile', str(outfile), '--process-count', '1', *extra]
    )
    tool.parse_arguments()
    tool.start()
    return json.loads(outfile.read_text())['runs'][0]


def test_diagnostics_list_every_file(target, tmp_path):
    run = scan(target, tmp_path / 'report.sarif', '--report-diagnostics')
    artifacts = {a['location']['uri']: a for a in run['artifacts']}

    scanned = artifacts['src/settings.py']
    assert scanned['properties']['status'] == 'ok'
    assert scanned['properties']['scanTimeMs'] > 0
    assert scanned['length'] == len('password = "T7r$kq92LmZx"\n')

    skipped = artifacts['node_modules/pkg/index.js']
    assert skipped['properties']['status'] == 'skipped'
    assert 'node_modules' in skipped['properties']['skipReason']
    assert 'scanTimeMs' not in skipped['properties']

    assert run['invocations'][0]['executionSuccessful'] is True


def test_report_unchanged_without_flag(target, tmp_path):
    run = scan(target, tmp_path / 'report.sarif')
    assert 'artifacts' not in run
    assert 'invocations' not in run


def test_error_list_is_per_file():
    # KI-CLI-08: a worker used to report the errors of every earlier file it handled
    clear_error_list()
    logger.error('first file failed')
    errors = get_error_list()
    assert errors == ['first file failed']

    clear_error_list()
    assert get_error_list() == []
    # the returned list is a copy, not the live buffer
    assert errors == ['first file failed']
