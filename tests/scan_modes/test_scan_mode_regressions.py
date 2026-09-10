import shutil
import threading
from multiprocessing.pool import ThreadPool
from pathlib import Path
from unittest.mock import Mock

from dotwiz import DotWiz

from deepsecrets.config import Config, Output
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.rules.hashed_secret import HashedSecretRule
from deepsecrets.core.model.rules.regex import RegexRule
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.utils.fs import get_path_inside_package
from deepsecrets.scan_modes.cli import CliScanMode

HASHED_SECRET = '$ecRetT0F1nD'  # sha1 listed in tests/fixtures/hashed_secrets.json, present in tests/fixtures/1.py


def _config(workdir: str) -> Config:
    config = Config()
    config.set_workdir(workdir)
    config.engines.append(RegexEngine)
    config.add_ruleset(RegexRulesetBuilder, ['tests/fixtures/regexes.json'])
    config.output = Output(type='sarif', path='/tmp/unused.sarif')
    return config


def _mock_progress_bar(mode: CliScanMode) -> None:
    mode.progress_bar = Mock()
    mode.progress_bar.add_task.return_value = 0
    mode.progress_bar.task_ids = []


def _run_with_timeout(mode: CliScanMode, timeout: int = 60):
    outcome = {}
    thread = threading.Thread(target=lambda: outcome.update(result=mode.run()), daemon=True)
    thread.start()
    thread.join(timeout=timeout)
    assert not thread.is_alive(), 'scan did not terminate'
    return outcome['result']


def test_trailing_slash_workdir_keeps_exclusions_relative(tmp_path: Path):
    # a parent directory matching a built-in exclusion ('vendor/') used to exclude the whole tree
    root = tmp_path / 'vendor' / 'proj'
    root.mkdir(parents=True)
    (root / 'app.py').write_text('password = "Xk9mQ2vL7pR4tZw8Jq"\n')

    config = _config(f'{root}/')
    config.set_global_exclusion_paths([get_path_inside_package('rules/excluded_paths.json')])
    mode = CliScanMode(config=config)
    try:
        assert config.workdir_path == str(root)
        assert mode.filepaths == [str(root / 'app.py')]
    finally:
        mode.dispose()


def test_worker_relative_path_with_repeated_workdir(tmp_path: Path):
    # the workdir path occurring again deeper in the tree used to be stripped too
    workdir = tmp_path / 'w'
    nested = Path(f'{workdir}/pkg{workdir}')
    nested.mkdir(parents=True)
    target = nested / 'app.py'
    target.write_text('password = "hunter2hunter2"\n')

    bundle = DotWiz(
        workdir=str(workdir),
        benchmarking_mode=False,
        engines={'regex': True},
        rulesets={'regex': [RegexRule(id='T1', name='test', pattern='hunter2hunter2')]},
    )
    result = CliScanMode._per_file_analyzer(bundle, str(target), 1, {})

    assert len(result.findings) == 1
    assert result.findings[0].file.relative_path == f'pkg{workdir}/app.py'


def test_worker_runs_hashed_engine():
    builder = HashedSecretsRulesetBuilder().with_rules_from_file('tests/fixtures/hashed_secrets.json')
    bundle = DotWiz(
        workdir='/app/tests/fixtures',
        benchmarking_mode=False,
        engines={'hashed': True},
        rulesets={'hashed': builder.rules},
    )
    reporter = {}
    result = CliScanMode._per_file_analyzer(bundle, '/app/tests/fixtures/1.py', 1, reporter)

    assert [finding.detection for finding in result.findings] == [HASHED_SECRET]
    assert isinstance(result.findings[0].rules[0], HashedSecretRule)
    assert reporter[1]['finished'] is True


class PartiallyExplodingScanMode(CliScanMode):
    @staticmethod
    def _per_file_analyzer(bundle, file, task_id=None, task_reporter=None):  # type: ignore
        if file.endswith('/json'):
            # leave the entry unfinished, exactly like an exception early in the real worker
            task_reporter[task_id] = {'started': True, 'failure': False, 'finished': False}
            raise RuntimeError('boom')
        return CliScanMode._per_file_analyzer(bundle, file, task_id, task_reporter)


def test_run_terminates_when_a_worker_raises():
    config = _config('tests/fixtures/extless')
    mode = PartiallyExplodingScanMode(config=config, pool_engine=ThreadPool)
    _mock_progress_bar(mode)
    try:
        assert len(mode.filepaths) == 4
        crashed = '/app/tests/fixtures/extless/json'

        findings, errors, _ = _run_with_timeout(mode)

        assert mode.stats.failed_files == 1
        assert mode.stats.finished == 4
        assert errors[crashed] == ['RuntimeError: boom']
        assert set(errors.keys()) == set(mode.filepaths)
        assert all(finding.file.path != crashed for finding in findings)
    finally:
        mode.dispose()


class RecordingPool(ThreadPool):
    """A thread pool that records what the scan sends to it."""

    last = None

    def __init__(self, *args, **kwargs):
        self.init_kwargs = kwargs
        self.task_args = []
        super().__init__(*args, **kwargs)
        RecordingPool.last = self

    def apply_async(self, func, args=(), kwds={}, callback=None, error_callback=None):
        self.task_args.append(args)
        return super().apply_async(func, args, kwds, callback, error_callback)


def test_bundle_reaches_workers_once_not_per_task():
    # pickling the bundle (compiled rules) with every file cost more than analysing a small file
    config = _config('tests/fixtures/extless')
    mode = CliScanMode(config=config, pool_engine=RecordingPool)
    _mock_progress_bar(mode)
    try:
        expected = []
        for file in mode.filepaths:
            expected.extend(mode._per_file_analyzer(mode.analyzer_bundle(), file, 0, {}).findings)

        findings, errors, _ = _run_with_timeout(mode)
        pool = RecordingPool.last

        bundle, reporter = pool.init_kwargs['initargs']
        assert isinstance(bundle, DotWiz)
        assert reporter is mode.active_task_reporter
        assert len(pool.task_args) == len(mode.filepaths)
        for args in pool.task_args:
            assert not any(isinstance(arg, DotWiz) for arg in args)
            assert reporter not in args
        assert sorted(f.detection for f in findings) == sorted(f.detection for f in expected)
        assert mode.stats.failed_files == 0
    finally:
        mode.dispose()


def test_hashed_scan_through_process_pool(tmp_path: Path):
    # the combination that used to hang: HashedSecretEngine registered, run in a real spawn pool
    shutil.copy('tests/fixtures/1.py', tmp_path / '1.py')
    config = Config()
    config.set_workdir(str(tmp_path))
    config.engines.append(HashedSecretEngine)
    config.add_ruleset(HashedSecretsRulesetBuilder, ['tests/fixtures/hashed_secrets.json'])
    config.output = Output(type='sarif', path='/tmp/unused.sarif')

    mode = CliScanMode(config=config)
    _mock_progress_bar(mode)
    try:
        findings, errors, _ = _run_with_timeout(mode, timeout=120)

        assert [finding.detection for finding in findings] == [HASHED_SECRET]
        assert findings[0].file.relative_path == '1.py'
        assert mode.stats.failed_files == 0
    finally:
        mode.dispose()
