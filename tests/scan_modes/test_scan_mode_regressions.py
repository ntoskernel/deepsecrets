import errno
import gc
import os
import pickle
import shutil
import signal
import subprocess
import sys
import threading
from dataclasses import FrozenInstanceError, fields
from multiprocessing import forkserver, get_all_start_methods
from multiprocessing.pool import ThreadPool
from pathlib import Path
from unittest.mock import Mock

import pytest

from deepsecrets.config import Config, Output
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.internal.processing import AnalyzerBundle
from deepsecrets.core.model.rules.hashed_secret import HashedSecretRule
from deepsecrets.core.model.rules.regex import RegexRule
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.utils.fs import get_path_inside_package
from deepsecrets.core.modes import iscan_mode
from deepsecrets.core.utils.multiprocessing_setup import pool_context
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

    bundle = AnalyzerBundle(
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
    bundle = AnalyzerBundle(
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


def test_analyzer_bundle_carries_what_workers_read():
    config = _config('tests/fixtures/extless')
    mode = CliScanMode(config=config)
    try:
        bundle = mode.analyzer_bundle()

        assert {f.name for f in fields(bundle)} == {'workdir', 'engines', 'rulesets', 'benchmarking_mode'}
        assert bundle.workdir == '/app/tests/fixtures/extless'
        assert bundle.engines == {'regex': True}
        assert list(bundle.rulesets) == ['regex']
        assert bundle.benchmarking_mode is False
        with pytest.raises(FrozenInstanceError):
            setattr(bundle, 'workdir', '/elsewhere')
        assert pickle.loads(pickle.dumps(bundle)) == bundle
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

        bundle_path, reporter, task_pids = pool.init_kwargs['initargs']
        # one shared slot per task id, where each worker records its pid (KI-CLI-37)
        assert len(task_pids) == len(mode.filepaths) + 1 and task_pids is mode.task_pids
        # the bundle travels as a path, so the payload written to each spawned child stays small (KI-CLI-32)
        assert isinstance(bundle_path, str) and len(pickle.dumps(bundle_path)) < 1024
        assert not os.path.exists(bundle_path)  # its staging directory goes with the pool
        # a thread pool shares the worker globals, so what the initializer loaded is visible here
        assert iscan_mode._worker_bundle == mode.analyzer_bundle()
        assert reporter is mode.active_task_reporter
        assert len(pool.task_args) == len(mode.filepaths)
        for args in pool.task_args:
            assert not any(isinstance(arg, AnalyzerBundle) for arg in args)
            assert reporter not in args
        assert sorted(f.detection for f in findings) == sorted(f.detection for f in expected)
        assert mode.stats.failed_files == 0
    finally:
        mode.dispose()


def test_hashed_scan_through_process_pool(tmp_path: Path):
    # the combination that used to hang: HashedSecretEngine registered, run in a real process pool
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


def test_broken_symlink_does_not_abort_discovery(tmp_path: Path):
    # a dangling symlink, and a symlink loop, used to raise out of _size_check and kill the whole
    # scan before it started. --max-file-size must be set: at the default 0 the check short-circuits
    # before os.path.getsize and this passes even against the unfixed code.
    (tmp_path / 'real.py').write_text('password = "Xk9mQ2vL7pR4tZw8Jq"\n')
    (tmp_path / 'dangling.py').symlink_to(tmp_path / 'gone.py')
    (tmp_path / 'loop_a').symlink_to(tmp_path / 'loop_b')
    (tmp_path / 'loop_b').symlink_to(tmp_path / 'loop_a')

    config = _config(str(tmp_path))
    config.set_max_file_size(10_000_000)
    mode = CliScanMode(config=config)
    try:
        assert mode.filepaths == [str(tmp_path / 'real.py')]
        assert mode.stats.skipped_files == 3
        for name in ('dangling.py', 'loop_a', 'loop_b'):
            assert mode.files[str(tmp_path / name)].status == 'skipped'
            assert mode.files[str(tmp_path / name)].skip_reason == 'broken_symlink'
    finally:
        mode.dispose()


def test_broken_symlink_skipped_without_a_size_limit(tmp_path: Path):
    # at the default --max-file-size of 0 a dangling symlink never crashed, it reached a worker that
    # could not open it and was reported as a per-file error. It is a skip with a reason now.
    (tmp_path / 'real.py').write_text('password = "Xk9mQ2vL7pR4tZw8Jq"\n')
    (tmp_path / 'dangling.py').symlink_to(tmp_path / 'gone.py')

    config = _config(str(tmp_path))
    assert config.max_file_size == 0
    mode = CliScanMode(config=config)
    try:
        assert mode.filepaths == [str(tmp_path / 'real.py')]
        assert mode.files[str(tmp_path / 'dangling.py')].skip_reason == 'broken_symlink'
        # skipped files carry no error, so they stay out of the per-file error report
        assert mode.per_file_errors() == {}
    finally:
        mode.dispose()


def test_unreadable_file_is_not_filed_as_oversized(tmp_path: Path, monkeypatch):
    # _size_check used to swallow OSError and return False, which the caller could only read as
    # 'too big' -- so an unreadable file was reported as max_file_size in --report-diagnostics SARIF
    (tmp_path / 'fine.txt').write_text('x' * 10)
    victim = tmp_path / 'victim.txt'
    victim.write_text('y' * 10)

    real_getsize = os.path.getsize

    def fake_getsize(path):
        if str(path) == str(victim):
            raise PermissionError(errno.EACCES, 'Permission denied', str(path))
        return real_getsize(path)

    monkeypatch.setattr(os.path, 'getsize', fake_getsize)

    config = _config(str(tmp_path))
    config.set_max_file_size(10_000_000)
    mode = CliScanMode(config=config)
    try:
        assert mode.filepaths == [str(tmp_path / 'fine.txt')]
        assert mode.files[str(victim)].skip_reason == 'unreadable:EACCES'
    finally:
        mode.dispose()


def _run_capturing(mode: CliScanMode, timeout: int = 60):
    outcome = {}

    def target():
        try:
            outcome['result'] = mode.run()
        except BaseException as e:  # the thread must report what run() raised
            outcome['error'] = e

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=timeout)
    assert not thread.is_alive(), 'scan did not terminate'
    return outcome


@pytest.mark.parametrize('start_method', ['forkserver', 'spawn', 'fork'])
# the scan runs in a thread here (_run_capturing), so fork warns about forking a multi-threaded process
@pytest.mark.filterwarnings('ignore:This process .* is multi-threaded:DeprecationWarning')
def test_worker_that_cannot_load_the_bundle_stops_the_scan(start_method):
    # KI-DM-30: an initializer that raised killed the worker, the pool replaced it, the replacement failed the same
    # way, and run() polled forever. Now the first task on such a worker fails with WorkerStartupError and run() stops.
    def corrupted_pool(**kwargs):
        with open(kwargs['initargs'][0], 'wb') as f:
            f.write(b'not a pickle')
        return pool_context(start_method, CliScanMode.worker_modules).Pool(**kwargs)

    config = _config('tests/fixtures/extless')
    config.set_process_count(2)
    mode = CliScanMode(config=config, pool_engine=corrupted_pool)
    _mock_progress_bar(mode)
    try:
        outcome = _run_capturing(mode, timeout=120)
        assert isinstance(outcome.get('error'), iscan_mode.WorkerStartupError)
        assert 'UnpicklingError' in str(outcome['error'])
    finally:
        mode.dispose()


def test_bundle_deleted_before_workers_start_is_staged_again(monkeypatch):
    # a temporary-file cleaner can delete the staged bundle; the scan re-stages it and the workers' retry succeeds
    monkeypatch.setattr(iscan_mode, 'BUNDLE_RETRY_DELAY', 0.5)

    def pool_after_cleaner(**kwargs):
        os.remove(kwargs['initargs'][0])
        return ThreadPool(**kwargs)

    config = _config('tests/fixtures/extless')
    mode = CliScanMode(config=config, pool_engine=pool_after_cleaner)
    _mock_progress_bar(mode)
    try:
        outcome = _run_capturing(mode)
        assert 'error' not in outcome, outcome.get('error')
        assert mode.stats.finished == 4 and mode.stats.failed_files == 0
    finally:
        mode.dispose()


def test_initializer_never_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(iscan_mode, 'BUNDLE_RETRY_DELAY', 0)
    iscan_mode.init_worker(str(tmp_path / 'missing.pickle'), {})
    assert iscan_mode._worker_bundle is None
    assert iscan_mode._worker_startup_error.startswith('FileNotFoundError')
    with pytest.raises(iscan_mode.WorkerStartupError, match='could not load the analyzer bundle'):
        iscan_mode.pool_wrapper(lambda *args: None, 1, 'any.py')


class WorkerKillingScanMode(CliScanMode):
    @staticmethod
    def _per_file_analyzer(bundle, file, task_id=None, task_reporter=None):  # type: ignore
        if file.endswith('/json'):
            os.kill(os.getpid(), signal.SIGKILL)  # what the OOM killer does
        return CliScanMode._per_file_analyzer(bundle, file, task_id, task_reporter)


@pytest.mark.parametrize('ci_mode', [True, False])
def test_killed_worker_fails_its_file_instead_of_hanging_the_scan(ci_mode):
    # KI-CLI-37: the pool replaced the dead worker but never reported its task, and run() waited forever
    config = _config('tests/fixtures/extless')
    config.set_process_count(2)
    config.set_ci_mode(ci_mode)
    mode = WorkerKillingScanMode(config=config)
    _mock_progress_bar(mode)
    try:
        outcome = _run_capturing(mode, timeout=120)
        assert 'error' not in outcome, outcome.get('error')
        _, errors, _ = outcome['result']
        killed = '/app/tests/fixtures/extless/json'
        assert len(errors[killed]) == 1 and errors[killed][0].startswith('WorkerLostError: the worker process')
        assert mode.stats.finished == 4 and mode.stats.failed_files == 1
        assert list(mode.lost_jobs) == [next(t for t, j in mode.file_jobs.items() if j.name == killed)]
    finally:
        mode.dispose()


def _sigint_handler_is_ignored(bundle, file, task_id=None, task_reporter=None):
    return signal.getsignal(signal.SIGINT) is signal.SIG_IGN


@pytest.mark.parametrize('start_method', ['forkserver', 'spawn', 'fork'])
def test_pool_workers_leave_ctrl_c_to_the_parent(tmp_path: Path, start_method):
    # init_worker is the only place a worker ignores SIGINT (KI-CLI-17): forkserver children inherit the server's
    # default handler, fork children the parent's, and importing iscan_mode no longer changes a handler
    # finalise earlier tests' pools now: collected while this pool starts the resource tracker, their semaphores
    # would call into it reentrantly, which it refuses with a "might leak" warning
    gc.collect()
    ctx = pool_context(start_method, CliScanMode.worker_modules)
    path = iscan_mode.stage_bundle(AnalyzerBundle(workdir=str(tmp_path)), str(tmp_path))
    with ctx.Pool(2, initializer=iscan_mode.init_worker, initargs=(path, None)) as pool:
        answers = pool.starmap(iscan_mode.pool_wrapper, [(_sigint_handler_is_ignored, i, 'x') for i in range(4)])
    assert answers == [True] * 4


def test_ci_mode_needs_no_manager_and_finds_the_same():
    results = {}
    for ci_mode in (False, True):
        config = _config('tests/fixtures/extless')
        config.set_process_count(2)
        config.set_ci_mode(ci_mode)
        mode = CliScanMode(config=config)
        _mock_progress_bar(mode)
        try:
            assert (mode._mp_manager is None) is ci_mode
            findings, errors, _ = _run_with_timeout(mode, timeout=120)
            results[ci_mode] = (sorted((f.file.path, f.start_offset, f.detection) for f in findings), errors)
            assert mode.stats.finished == 4
            if ci_mode:
                assert mode.stats.total_findings == len(findings)
        finally:
            mode.dispose()
    assert results[True] == results[False]


FORKSERVER_STOP_SCRIPT = """
import os, sys, time
from multiprocessing import forkserver
from deepsecrets.config import Config, Output
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.utils.multiprocessing_setup import pool_context, start_manager, stop_forkserver
from deepsecrets.scan_modes.cli import CliScanMode

config = Config()
config.set_workdir('tests/fixtures/extless')
config.engines.append(RegexEngine)
config.add_ruleset(RegexRulesetBuilder, ['tests/fixtures/regexes.json'])
config.output = Output(type='sarif', path='/tmp/unused.sarif')
config.set_process_count(2)
config.set_mp_context('forkserver')
config.set_ci_mode(True)
mode = CliScanMode(config=config)
mode.run()
mode.dispose()
server = forkserver._forkserver._forkserver_pid
print('stopped', stop_forkserver())
try:
    os.waitpid(server, os.WNOHANG)
    print('reaped', False)
except ChildProcessError:
    print('reaped', True)

# another process the server started holds its alive pipe: the stop must not wait for it
extra = start_manager(pool_context('forkserver', []))
server = forkserver._forkserver._forkserver_pid
began = time.monotonic()
print('stopped', stop_forkserver(timeout=0.5), 'fast' if time.monotonic() - began < 5 else 'slow')
extra.shutdown()
os.waitpid(server, 0)  # exits with its last child
print('exited', True)
"""


@pytest.mark.skipif('forkserver' not in get_all_start_methods(), reason='no forkserver on this platform')
def test_stop_forkserver_accounts_the_workers_and_never_hangs():
    # KI-CLI-42: the server reaps the workers; left running, it outlived the scan as an orphan, so their CPU time
    # never reached `time` or a harness that waits for the scanner (7x too little on the fixtures). In a subprocess,
    # because other tests leave forkserver-started managers alive in this one.
    env = dict(os.environ, PYTHONPATH=os.getcwd())
    out = subprocess.run(
        [sys.executable, '-c', FORKSERVER_STOP_SCRIPT], env=env, capture_output=True, text=True, timeout=180
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.split('\n')[-5:] == ['stopped True', 'reaped True', 'stopped False fast', 'exited True', '']


