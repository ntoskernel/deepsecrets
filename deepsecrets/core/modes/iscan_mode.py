from deepsecrets.core.ui.progress_bar import DSApplicationProgess
from deepsecrets.utils import setup_interrupts_for_subprocess

setup_interrupts_for_subprocess()
import time

from dataclasses import dataclass, field
from functools import partial
from multiprocessing.pool import AsyncResult
from queue import SimpleQueue
import regex as re

import contextlib
from multiprocessing.managers import DictProxy
import errno
import os
import pickle
import tempfile
from abc import abstractmethod
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from deepsecrets import PROFILER_ON, console
from deepsecrets.config import Config
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.internal.processing import AnalyzerBundle, PerFileAnalysisResult
from deepsecrets.core.model.rules.exlcuded_path import ExcludePathRule
from deepsecrets.core.rulesets.excluded_paths import ExcludedPathsBuilder
from deepsecrets.core.rulesets.false_findings import FalseFindingsBuilder
from deepsecrets.core.utils.file_analyzer import FileAnalyzer
from deepsecrets.core.utils.finding_merger import FindingMerger
from deepsecrets.core.utils.fs import get_abspath, get_relative_path
from deepsecrets.core.utils.log import logger
from deepsecrets.core.utils.multiprocessing_setup import pool_context, start_manager
from deepsecrets.utils import setup_interrupts_for_subprocess

from rich.progress import Progress as ProgressBar
from rich.live import Live
from rich.text import Text


class WorkerStartupError(RuntimeError):
    """A pool worker could not load the analyzer bundle, so every file it took would fail the same way."""


class WorkerLostError(RuntimeError):
    """The worker process analysing a file exited without reporting a result (killed, or out of memory)."""


# seconds between noticing that a worker exited and failing the file it held, so a result it sent just before
# exiting can still arrive
LOST_WORKER_GRACE_SECONDS = 0.5
# in CI mode, a plain progress line every this many seconds
CI_PROGRESS_INTERVAL_SECONDS = 30.0


@dataclass
class FileJob:
    internal_id: int
    pb_task_id: Optional[int]
    name: str
    result_holder: AsyncResult


@dataclass
class FileOutcome:
    """What happened to one file, scanned or skipped. `FileJob` tracks a job while it runs; this is what is left
    when it is done, and it is what `--report-diagnostics` turns into SARIF artifacts."""

    path: str
    # scheduled -> ok | empty | unreadable | error, or skipped for a file the scan never opened
    status: str = 'scheduled'
    skip_reason: Optional[str] = None
    time_ms: float = 0.0
    collected: bool = False
    errors: List[str] = field(default_factory=list)

    @property
    def time_seconds(self) -> int:
        return int(self.time_ms / 1000)


@dataclass
class Stats:
    total_files: int = 0
    skipped_files: int = 0
    finished: int = 0
    failed_files: int = 0
    tokens_processed: int = 0
    total_findings: int = 0
    finished_ids: set[int] = field(default_factory=set)

    def new_finished(self, tid):
        self.finished_ids.add(tid)
        self.finished = len(self.finished_ids)


class ScanMode:
    config: Config
    filepaths: List[str]
    path_exclusion_rules: List[ExcludePathRule] = []
    file_analyzer: FileAnalyzer
    pool_engine: Type
    rulesets: Dict[str, List]
    engines_enabled: Dict[str, bool]

    active_task_reporter: DictProxy
    progress_bar: DSApplicationProgess

    file_results: List[AsyncResult]
    file_jobs: Dict[int, FileJob]
    # path -> outcome, for every file found under the target dir
    files: Dict[str, FileOutcome]

    _mp_manager = None
    # modules a forkserver imports before forking workers, so they share them (see pool_context)
    worker_modules: List[str] = []

    # ONLY IN BENCHMARKING MODE
    _oneshot_file: Optional[File] = None

    def __init__(self, config: Config, pool_engine: Optional[Any] = None) -> None:
        console.print('[*] Looking for applicable files...', end='')
        console.line()
        self.mp_context = pool_context(config.mp_context, self.worker_modules)
        if pool_engine is None:
            self.pool_engine = self.mp_context.Pool
        else:
            self.pool_engine = pool_engine

        # CI mode reports no per-file progress, so it needs no manager process (and no manager socket)
        self._mp_manager = None if config.ci_mode else start_manager(self.mp_context)
        self.active_task_reporter = self._mp_manager.dict({}) if self._mp_manager is not None else None
        self.progress_bar = None

        self.config = config
        self.file_results = []
        self.file_jobs = {}
        self.failed_jobs = SimpleQueue()
        self.done_jobs = SimpleQueue()
        self.startup_error: Optional[str] = None
        # task id -> pid of the worker that took it, written by the worker (pool_wrapper), for reap_lost_jobs
        self.task_pids = None
        self.lost_jobs: Dict[int, int] = {}
        self._worker_pids_seen: set = set()
        self._worker_gone_at: Dict[int, float] = {}
        self._worker_pids_handled: set = set()
        self.stats = Stats()
        self.files = {}

        self.filepaths = self._get_files_list()
        self.prepare_for_scan()

    def set_progress_bar(self, progress_bar: ProgressBar):
        self.progress_bar = progress_bar

    def stop_progress_bar(self, overall_progress):
        if not self.progress_bar:
            return

        self.refresh_jobs_progress_bars()
        self.refresh_overall_progress_bar(overall_progress)
        for task_id in self.progress_bar.task_ids:
            if task_id == overall_progress:
                continue
            self.progress_bar.remove_task(task_id=task_id)
        self.progress_bar.stop()

    def _get_process_count_for_runner(self) -> int:
        limit = self.config.process_count

        file_count = len(self.filepaths)
        if file_count == 0:
            return 0
        return limit if file_count >= limit else file_count

    def refresh_jobs_progress_bars(self):
        if self.active_task_reporter is None:
            return

        tasks_to_remove = set()

        for internal_task_id, current_state in self.active_task_reporter.items():
            if current_state is None:
                continue

            if internal_task_id in self.stats.finished_ids:
                # a late write for a job that is already accounted for
                tasks_to_remove.add(internal_task_id)
                continue

            job = self.file_jobs.get(internal_task_id)
            if job is None:
                raise Exception()

            started: bool = current_state.get('started')
            finished: bool = current_state.get('finished')
            failure: bool = current_state.get('failure')

            size: str = current_state.get('file_size')

            if started is True and finished is False and job.pb_task_id is None:
                job.pb_task_id = self.progress_bar.add_task(
                    f'[{job.internal_id}] {job.name.split("/")[-1]}',
                    findings='0',
                    errors='',
                    size='| ? Kb',
                )

            processed = current_state.get('processed', 0)
            findings = current_state.get('findings', 0)

            if finished is True:
                tasks_to_remove.add(internal_task_id)

                if failure is True:
                    self.stats.failed_files += 1
                else:
                    self.stats.tokens_processed += processed
                    self.stats.total_findings += findings

                if job.pb_task_id is not None:
                    try:
                        self.progress_bar.remove_task(job.pb_task_id)
                    except Exception:
                        pass
                continue

            total = current_state.get('total_tokens')
            completed = current_state.get('percentage')

            if job.pb_task_id is not None:
                self.progress_bar.update(
                    job.pb_task_id,
                    completed=completed,
                    total=100,
                    visible=True,
                    findings=findings,
                    size=f'| {size}',
                )

        for to_remove in tasks_to_remove:
            self.active_task_reporter.pop(to_remove)
            self.stats.new_finished(to_remove)

    def _on_job_error(self, task_id: int, error: BaseException) -> None:
        # Called by the pool's result handler thread when a job raised
        if isinstance(error, WorkerStartupError):
            self.startup_error = str(error)
        self.failed_jobs.put(task_id)

    def _on_job_done(self, task_id: int, result: PerFileAnalysisResult) -> None:
        # Called by the pool's result handler thread when a job returned; CI mode counts completion from this
        self.done_jobs.put((task_id, len(result.findings or [])))

    def _new_task_pids(self) -> Any:
        # one slot per task id (they start at 1); shared memory, so a worker's write costs no message to the parent
        self.task_pids = self.mp_context.RawArray('i', len(self.filepaths) + 1)
        return self.task_pids

    def reap_done_jobs(self) -> None:
        while not self.done_jobs.empty():
            task_id, findings = self.done_jobs.get()
            if task_id in self.stats.finished_ids:
                continue
            self.stats.total_findings += findings
            self.stats.new_finished(task_id)

    def reap_lost_jobs(self, pool: Any) -> None:
        """Fail the file a killed worker was analysing (KI-CLI-37).

        A worker killed outright (OOM killer, SIGKILL) takes its task with it: the pool starts a replacement but never
        reports the task, so the scan used to wait forever. Each worker writes its pid into `task_pids` when it takes
        a file; a pid that has left the pool's worker list for longer than LOST_WORKER_GRACE_SECONDS marks every
        unfinished file it took as lost."""
        if self.task_pids is None:
            return
        live = {pid for pid in (getattr(worker, 'pid', None) for worker in list(getattr(pool, '_pool', []))) if pid}
        if not live and not self._worker_pids_seen:
            return  # a thread pool: its workers cannot exit on their own
        self._worker_pids_seen |= live
        now = time.monotonic()
        for pid in self._worker_pids_seen - live - self._worker_pids_handled:
            self._worker_gone_at.setdefault(pid, now)
        gone = {pid for pid, at in self._worker_gone_at.items() if now - at >= LOST_WORKER_GRACE_SECONDS}
        gone -= self._worker_pids_handled
        if not gone:
            return
        self._worker_pids_handled |= gone
        for task_id, job in self.file_jobs.items():
            pid = self.task_pids[task_id]
            if pid not in gone or task_id in self.lost_jobs or job.result_holder.ready():
                continue
            self.lost_jobs[task_id] = pid
            fail_lost_task(
                job.result_holder,
                WorkerLostError(
                    f'the worker process {pid} exited while analysing this file (killed, or out of memory)'
                ),
            )

    def report_plain_progress(self, force: bool = False) -> None:
        """CI mode's progress: a plain line every CI_PROGRESS_INTERVAL_SECONDS instead of live bars."""
        now = time.monotonic()
        if not force and now - self._last_plain_progress < CI_PROGRESS_INTERVAL_SECONDS:
            return
        self._last_plain_progress = now
        console.print(
            f'[*] {self.stats.finished}/{self.stats.total_files} files scanned, '
            f'{self.stats.failed_files} failed, {self.stats.total_findings} findings before merging',
            highlight=False,
        )

    def reap_failed_jobs(self) -> None:
        # A job that raised never reports 'finished', so without this run() would poll forever
        while not self.failed_jobs.empty():
            task_id = self.failed_jobs.get()
            if task_id in self.stats.finished_ids:
                continue

            self.stats.failed_files += 1
            self.stats.new_finished(task_id)
            if self.active_task_reporter is not None:
                self.active_task_reporter.pop(task_id, None)

            job = self.file_jobs.get(task_id)
            if job is not None and job.pb_task_id is not None:
                try:
                    self.progress_bar.remove_task(job.pb_task_id)
                except Exception:
                    pass

    def refresh_overall_progress_bar(self, pb_task_id):
        if pb_task_id is None:
            return

        self.progress_bar.update(
            pb_task_id,
            completed=self.stats.finished,
            total=self.stats.total_files,
            findings=f'F: {self.stats.total_findings}',
            errors=f'ERR: {self.stats.failed_files}',
            size=f'{self.stats.finished}/{self.stats.total_files}',
        )

    def run(self) -> Tuple[List[Finding], Dict[str, List[str]], Dict[str, int]]:
        final: List[Finding] = []

        bundle = self.analyzer_bundle()
        proc_count = self._get_process_count_for_runner()
        if proc_count == 0:
            return final, self.per_file_errors(), self.per_file_timings()

        overall_progress_task = None
        if self.progress_bar is not None:
            overall_progress_task = self.progress_bar.add_task(
                "[green bold]OVERALL\nPROGRESS\n",
                visible=True,
                findings='F: 0',
                errors='ERR: 0',
                size=f'0/{self.stats.total_files}',
            )
        ci_mode = self.config.ci_mode
        self._last_plain_progress = time.monotonic()

        if PROFILER_ON:
            for file in self.filepaths:
                final.extend(
                    self._per_file_analyzer(
                        file=file, bundle=bundle, task_id=0, task_reporter=self.task_reporter
                    ).findings
                )
        else:
            try:
                # the bundle and the reporter proxy reach each worker once, not with every file; the bundle as a
                # path, because in initargs it would make spawned workers start one at a time (KI-CLI-32)
                with (
                    tempfile.TemporaryDirectory(prefix='deepsecrets-') as staging,
                    self.pool_engine(
                        processes=proc_count,
                        initializer=init_worker,
                        initargs=(stage_bundle(bundle, staging), self.active_task_reporter, self._new_task_pids()),
                    ) as pool,
                ):
                    tid = 0
                    for file in self.filepaths:
                        tid += 1
                        result = pool.apply_async(
                            pool_wrapper,
                            (self._per_file_analyzer, tid, file),
                            callback=partial(self._on_job_done, tid) if ci_mode else None,
                            error_callback=partial(self._on_job_error, tid),
                        )
                        self.file_results.append(result)
                        self.file_jobs[tid] = FileJob(name=file, internal_id=tid, pb_task_id=None, result_holder=result)
                    pool.close()

                    self.stats.total_files = len(self.file_jobs.keys())
                    while self.stats.finished < self.stats.total_files:
                        # a worker that cannot load the bundle would fail every file it takes: stop, don't poll
                        # for results that cannot come (KI-DM-30)
                        if self.startup_error is not None:
                            raise WorkerStartupError(self.startup_error)
                        keep_bundle_staged(bundle, staging)
                        self.refresh_jobs_progress_bars()
                        self.reap_done_jobs()
                        self.reap_lost_jobs(pool)
                        self.reap_failed_jobs()
                        self.refresh_overall_progress_bar(overall_progress_task)
                        if ci_mode:
                            self.report_plain_progress()
                        time.sleep(0.1)
                        # self.refresh_overall_debug_progress_bar(overall_debug)
                    self.stop_progress_bar(overall_progress_task)
                    if ci_mode:
                        self.report_plain_progress(force=True)
                    console.print('[*] Collecting results..')
                    pool.join()

            except KeyboardInterrupt:
                if getattr(self, 'progress_bar', None):
                    self.stop_progress_bar(overall_progress_task)

                console.print(
                    "\n[bold red][!] Scan abort request was received (Ctrl+C).\n    Intermediate results will NOT be saved.\n    Shutting down workers...[/bold red]"
                )

                if 'pool' in locals():
                    pool.terminate()
                    pool.join()

                if getattr(self, '_mp_manager', None):
                    self._mp_manager.shutdown()

                raise

            for job in self.file_jobs.values():
                outcome = self.files.setdefault(job.name, FileOutcome(path=job.name))
                try:
                    analysis_result: PerFileAnalysisResult = job.result_holder.get(timeout=1000)
                except Exception as e:
                    # reported as a failed file, like a file that cannot be opened
                    logger.error(f'Analysis of {job.name} failed: {type(e).__name__}: {e}')
                    outcome.status = 'error'
                    outcome.errors = [f'{type(e).__name__}: {e}']
                    continue

                self._oneshot_file = analysis_result._file
                outcome.collected = True
                outcome.time_ms = analysis_result.processing_time_ms
                outcome.errors = analysis_result.errors
                # a file that logged an error is reported as failed even when the analysis returned
                status = analysis_result.status
                outcome.status = 'error' if status == 'ok' and analysis_result.errors else status

                if analysis_result.findings is None or len(analysis_result.findings) == 0:
                    continue
                final.extend(analysis_result.findings)

        console.line()
        console.print('[*] Merging similar findings..')
        fin = FindingMerger(final).merge()

        console.print('[*] Filtering predefined false Findings..')
        fin = self.filter_false_positives(fin)
        return fin, self.per_file_errors(), self.per_file_timings()

    def dispose(self):
        self.task_reporter = None
        if self._mp_manager is not None:
            self._mp_manager.shutdown()
        print()

    def _get_files_list(self) -> List[str]:
        flist = []
        if not self.path_exclusion_rules:
            excl_paths_builder = ExcludedPathsBuilder()
            for path in self.config.global_exclusion_paths:
                excl_paths_builder.with_rules_from_file(path)

            self.path_exclusion_rules = excl_paths_builder.rules

        if self.config.oneshot_path is not None:
            path = get_abspath(self.config.oneshot_path)
            self.files[path] = FileOutcome(path=path)
            flist.append(path)
            return flist

        # CI mode: no live counter, which only redraws in a build log
        with contextlib.nullcontext() if self.config.ci_mode else Live(console=console, refresh_per_second=5) as live:
            total_files = 0
            for fpath, _, files in os.walk(get_abspath(self.config.workdir_path)):
                for filename in files:
                    total_files += 1
                    if live is not None:
                        live.update(Text(text=f'Found {total_files} files, {self.stats.skipped_files} will be skipped'))
                    full_path = os.path.join(fpath, filename)
                    rel_path = get_relative_path(full_path, self.config.workdir_path)
                    exclusion = self._matching_exclusion(rel_path)
                    if exclusion is not None:
                        self._skip(full_path, f'excluded_path:{exclusion}')
                        continue

                    if os.path.islink(full_path) and not os.path.exists(full_path):
                        # a dangling symlink or a symlink loop -- os.path.exists is False for both. Skipping here
                        # keeps it away from a worker that could not open it, and away from _size_check below,
                        # where os.path.getsize raises once --max-file-size is set.
                        self._skip(full_path, 'broken_symlink')
                        continue

                    try:
                        size_ok = self._size_check(full_path)
                    except OSError as e:
                        # vanished or became unreadable between os.walk and here
                        self._skip(full_path, f'unreadable:{errno.errorcode.get(e.errno, e.errno)}')
                        continue

                    if not size_ok:
                        self._skip(full_path, 'max_file_size')
                        '''
                        console.print(
                            f'[bold yellow]:warning: {rel_path}[/bold yellow]: File size exceeds [magenta]--max-file-path[/magenta] of {self.config.max_file_size} bytes and will be [bold]skipped[/bold]'
                        )
                        '''
                        continue

                    self.files[full_path] = FileOutcome(path=full_path)
                    flist.append(full_path)

        return flist

    def _skip(self, path: str, reason: str) -> None:
        self.files[path] = FileOutcome(path=path, status='skipped', skip_reason=reason)
        self.stats.skipped_files += 1

    def per_file_errors(self) -> Dict[str, List[str]]:
        """Error lists for every file the scan tried to analyse, skipped ones excluded."""
        return {path: o.errors for path, o in self.files.items() if o.status not in ('skipped', 'scheduled')}

    def per_file_timings(self) -> Dict[str, int]:
        """Whole seconds per analysed file: the shape benchmarking mode has always returned."""
        return {path: o.time_seconds for path, o in self.files.items() if o.collected}

    def _path_included(self, path: str) -> bool:
        return self._matching_exclusion(path) is None

    def _matching_exclusion(self, path: str) -> Optional[str]:
        """The pattern of the first exclusion rule that matches `path`, or None."""
        if self.path_exclusion_rules is None or len(self.path_exclusion_rules) == 0:
            return None

        for excl_rule in self.path_exclusion_rules:
            if excl_rule.match(path):
                return excl_rule.pattern.pattern
        return None

    def _size_check(self, path: str):
        """True when `path` is within `--max-file-size`. Raises `OSError` when the path cannot be stat'ed:
        the caller records that under its own skip reason, distinct from a genuinely oversized file."""
        if self.config.max_file_size == 0:
            return True

        size = os.path.getsize(path)
        if size > self.config.max_file_size:
            return False
        return True

    @abstractmethod
    def prepare_for_scan(self) -> None:
        pass

    def analyzer_bundle(self) -> AnalyzerBundle:
        return AnalyzerBundle(
            workdir=self.config.workdir_path,
            benchmarking_mode=self.config._benchmarking_mode,
        )

    @staticmethod
    @abstractmethod
    def _per_file_analyzer(bundle: AnalyzerBundle, file: Any, task_id: Optional[int] = None, task_reporter: Optional[Any] = None) -> PerFileAnalysisResult:  # type: ignore
        pass

    def filter_false_positives(self, results: List[Finding]) -> List[Finding]:
        false_finding_rules = self.rulesets.get(FalseFindingsBuilder.ruleset_name)
        if false_finding_rules is None:
            return results

        final: List[Finding] = []
        for result in results:
            good_result = True
            for false_pattern in false_finding_rules:
                if re.match(false_pattern.pattern, result.detection) is not None:
                    good_result = False
                    break
            if not good_result:
                continue

            final.append(result)

        return final


_worker_bundle: Optional[AnalyzerBundle] = None
_worker_task_reporter: Optional[DictProxy] = None


def stage_bundle(bundle: AnalyzerBundle, directory: str) -> str:
    """Write the bundle once, for every worker's initializer to load.

    Passing the bundle itself in `initargs` puts it in the payload the spawn launcher writes to each child's pipe in a
    single call. When that payload is larger than the pipe buffer (8 KB on some hosts; the rules alone are about
    33 KB) the parent blocks until the child has re-imported the package, so workers start one at a time: 64 of them
    took 55 s. A path is a few bytes, however many rules there are (KI-CLI-32).
    """
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, 'bundle.pickle')
    with open(path, 'wb') as f:
        pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)
    return path


def keep_bundle_staged(bundle: AnalyzerBundle, directory: str) -> None:
    """Stage the bundle again if something deleted it mid-scan, such as a temporary-file cleaner. Workers that already
    started do not need it, but the pool replaces any worker that exits, and the replacement loads it afresh."""
    if not os.path.exists(os.path.join(directory, 'bundle.pickle')):
        stage_bundle(bundle, directory)


# seconds a worker waits before its one retry of a failed bundle load, which covers the parent re-staging it
BUNDLE_RETRY_DELAY = 0.5
_worker_bundle_path: Optional[str] = None
_worker_startup_error: Optional[str] = None
_worker_task_pids: Any = None


def _load_bundle(bundle_path: str) -> AnalyzerBundle:
    # written by this scan into a private temporary directory (mkdtemp creates it 0700)
    with open(bundle_path, 'rb') as f:
        return pickle.load(f)


def init_worker(bundle_path: str, task_reporter: DictProxy, task_pids: Any = None) -> None:  # pragma: nocover
    # Pool initializer: runs once per worker. Pickling the bundle (compiled rules) and the proxy
    # with every task cost more than analysing a typical small file.
    # It must not raise: the pool would replace the worker, the replacement would fail the same way, and the scan
    # would wait forever for results (KI-DM-30). The failure is kept for the worker's first task to report.
    global _worker_bundle, _worker_task_reporter, _worker_bundle_path, _worker_startup_error, _worker_task_pids
    # a forkserver worker inherits the server's handlers, where this module was imported as the main process, so the
    # import-time call at the top of this module did nothing there: Ctrl+C belongs to the parent
    setup_interrupts_for_subprocess()
    _worker_task_reporter = task_reporter
    _worker_task_pids = task_pids
    _worker_bundle_path = bundle_path
    try:
        _worker_bundle = _load_bundle(bundle_path)
        _worker_startup_error = None
    except Exception as e:
        _worker_bundle = None
        _worker_startup_error = f'{type(e).__name__}: {e}'


def _bundle_or_raise() -> AnalyzerBundle:
    global _worker_bundle, _worker_startup_error
    if _worker_bundle is None:
        time.sleep(BUNDLE_RETRY_DELAY)
        try:
            _worker_bundle = _load_bundle(_worker_bundle_path)
            _worker_startup_error = None
        except Exception as e:
            raise WorkerStartupError(
                f'a worker could not load the analyzer bundle ({_worker_startup_error}; retry: {type(e).__name__}: {e})'
            ) from e
    return _worker_bundle


def pool_wrapper(runner: Callable, task_id: Optional[int], file: str) -> PerFileAnalysisResult:  # pragma: nocover
    if _worker_task_pids is not None and isinstance(task_id, int) and 0 <= task_id < len(_worker_task_pids):
        _worker_task_pids[task_id] = os.getpid()  # lets the parent fail this file if this process dies (KI-CLI-37)
    result = runner(_bundle_or_raise(), file, task_id, _worker_task_reporter)
    return result


def fail_lost_task(result: AsyncResult, error: BaseException) -> None:
    """Complete a task whose worker died with `error`, as if the task had raised it: the error callback runs, `get()`
    raises it, and the pool stops waiting for it, so `join()` returns. Uses `ApplyResult._set`, the method the pool's
    own result handler calls; a result that arrives later is ignored by the pool."""
    setter = getattr(result, '_set', None)
    if setter is not None and not result.ready():
        setter(0, (False, error))
