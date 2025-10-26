from dataclasses import dataclass
from multiprocessing.pool import AsyncResult
import regex as re

from multiprocessing import Manager, get_context
from multiprocessing.managers import DictProxy
import os
from abc import abstractmethod
from typing import Any, Callable, Dict, List, Optional, Type

from dotwiz import DotWiz

from deepsecrets import PROFILER_ON, console
from deepsecrets.config import Config
from deepsecrets.core.model.finding import Finding, FindingMerger
from deepsecrets.core.model.rules.exlcuded_path import ExcludePathRule
from deepsecrets.core.rulesets.excluded_paths import ExcludedPathsBuilder
from deepsecrets.core.rulesets.false_findings import FalseFindingsBuilder
from deepsecrets.core.utils.file_analyzer import FileAnalyzer
from deepsecrets.core.utils.fs import get_abspath

from rich.progress import Progress as ProgressBar
from rich.live import Live
from rich.text import Text


@dataclass
class FileJob:
    internal_id: int
    name: str
    pb_task_id: Optional[int]
    result: AsyncResult


@dataclass
class Stats:
    total_files: int = 0
    finished: int = 0
    tokens_processed: int = 0
    total_findings: int = 0


class ScanMode:
    config: Config
    filepaths: List[str]
    path_exclusion_rules: List[ExcludePathRule] = []
    file_analyzer: FileAnalyzer
    pool_engine: Type
    rulesets: Dict[str, List]
    engines_enabled: Dict[Type, bool]

    active_task_reporter: DictProxy
    progress_bar: ProgressBar

    file_results: List[AsyncResult]
    file_jobs: Dict[int, FileJob]

    _mp_manager = None

    def __init__(self, config: Config, pool_engine: Optional[Any] = None) -> None:
        console.print('[*] Looking for applicable files...', end='')
        console.line()
        if pool_engine is None:
            self.pool_engine = get_context(config.mp_context).Pool
        else:
            self.pool_engine = pool_engine

        self._mp_manager = Manager()
        self.active_task_reporter = self._mp_manager.dict({})
        self.progress_bar = None

        self.config = config
        self.file_results = []
        self.file_jobs = {}
        self.stats = Stats()

        self.filepaths = self._get_files_list()
        self.prepare_for_scan()

    def set_progress_bar(self, progress_bar: ProgressBar):
        self.progress_bar = progress_bar

    def _get_process_count_for_runner(self) -> int:
        limit = self.config.process_count

        file_count = len(self.filepaths)
        if file_count == 0:
            return 0
        return limit if file_count >= limit else file_count

    def refresh_jobs_progress_bars(self):
        if self.active_task_reporter is None:
            return

        tasks_to_remove = []
        for internal_task_id, current_state in self.active_task_reporter.items():
            job = self.file_jobs.get(internal_task_id)
            if job is None:
                raise Exception()

            started: bool = current_state.get('started')
            finished: bool = current_state.get('finished')
            size: str = current_state.get('file_size')

            if started is True and finished is False and job.pb_task_id is None:
                job.pb_task_id = self.progress_bar.add_task(
                    f'[{job.internal_id}] {job.name.split("/")[-1]}',
                    findings='0',
                    size='| ? Kb',
                )

            processed = current_state.get('processed', 0)
            findings = current_state.get('findings', 0)

            if finished is True:
                self.stats.tokens_processed += processed
                self.stats.total_findings += findings

                tasks_to_remove.append(internal_task_id)
                if job.pb_task_id is not None:
                    try:
                        self.progress_bar.remove_task(job.pb_task_id)
                    except Exception:
                        pass
                continue

            total = current_state.get('total_tokens')

            if job.pb_task_id is not None:
                self.progress_bar.update(
                    job.pb_task_id,
                    completed=processed,
                    total=total,
                    visible=True,
                    findings=findings,
                    size=f'| {size}',
                )

        for to_remove in tasks_to_remove:
            self.stats.finished += 1
            self.active_task_reporter.pop(to_remove)

    def refresh_overall_progress_bar(self, pb_task_id):
        if pb_task_id is None:
            return

        self.progress_bar.update(
            pb_task_id,
            completed=self.stats.finished,
            total=self.stats.total_files,
            findings=f'FOUND: {self.stats.total_findings}',
        )

    def run(self) -> List[Finding]:
        final: List[Finding] = []
        bundle = self.analyzer_bundle()
        proc_count = self._get_process_count_for_runner()
        if proc_count == 0:
            return final

        overall_progress_task = self.progress_bar.add_task(
            "[green bold]OVERALL PROGRESS\n", visible=True, findings='FOUND: 0', size=''
        )

        if PROFILER_ON:
            for file in self.filepaths:
                final.extend(
                    self._per_file_analyzer(file=file, bundle=bundle, task_id=0, task_reporter=self.task_reporter)
                )
        else:
            with self.pool_engine(processes=proc_count) as pool:
                tid = 0
                for file in self.filepaths:
                    tid += 1
                    # runnable = partial(pool_wrapper, bundle, self._per_file_analyzer, self.task_reporter)
                    result = pool.apply_async(
                        pool_wrapper,
                        (bundle, self._per_file_analyzer, tid, self.active_task_reporter, file),
                    )
                    self.file_results.append(result)
                    self.file_jobs[tid] = FileJob(
                        name=file,
                        internal_id=tid,
                        result=result,
                        pb_task_id=None,
                    )
                pool.close()

                self.stats.total_files = len(self.file_jobs.keys())
                while self.stats.finished < self.stats.total_files:
                    self.refresh_jobs_progress_bars()
                    self.refresh_overall_progress_bar(overall_progress_task)
                pool.join()

        self.progress_bar.stop()

        for job_result in self.file_results:
            file_findings = job_result.get()
            if file_findings is None or len(file_findings) == 0:
                continue
            final.extend(file_findings)

        console.line()
        console.print('[*] Merging similar findings..')
        fin = FindingMerger(final).merge()

        console.print('[*] Filtering predefined false Findings..')
        fin = self.filter_false_positives(fin)
        return fin

    def dispose(self):
        self.task_reporter = None
        self._mp_manager.shutdown()
        print()

    def _get_files_list(self) -> List[str]:
        flist = []
        if not self.path_exclusion_rules:
            excl_paths_builder = ExcludedPathsBuilder()
            for path in self.config.global_exclusion_paths:
                excl_paths_builder.with_rules_from_file(path)

            self.path_exclusion_rules = excl_paths_builder.rules
        with Live(console=console, refresh_per_second=5) as live:

            total_files = 0
            skipped = 0
            for fpath, _, files in os.walk(get_abspath(self.config.workdir_path)):
                for filename in files:
                    live.update(Text(text=f'Found {total_files} files, {skipped} will be skipped'))
                    total_files += 1
                    full_path = os.path.join(fpath, filename)
                    rel_path = full_path.replace(f'{self.config.workdir_path}/', '')
                    if not self._path_included(rel_path):
                        skipped += 1
                        continue

                    if not self._size_check(full_path):
                        skipped += 1
                        '''
                        console.print(
                            f'[bold yellow]:warning: {rel_path}[/bold yellow]: File size exceeds [magenta]--max-file-path[/magenta] of {self.config.max_file_size} bytes and will be [bold]skipped[/bold]'
                        )
                        '''
                        continue

                    flist.append(full_path)

        return flist

    def _path_included(self, path: str) -> bool:
        if self.path_exclusion_rules is None or len(self.path_exclusion_rules) == 0:
            return True

        if any(excl_rule.match(path) for excl_rule in self.path_exclusion_rules):
            return False
        return True

    def _size_check(self, path: str):
        if self.config.max_file_size == 0:
            return True

        size = os.path.getsize(path)
        if size > self.config.max_file_size:
            return False
        return True

    @abstractmethod
    def prepare_for_scan(self) -> None:
        pass

    def analyzer_bundle(self) -> DotWiz:
        return DotWiz(
            logging_level=self.config.logging_level,
            max_file_size=self.config.max_file_size,
            workdir=self.config.workdir_path,
            path_exclusion_rules=self.path_exclusion_rules,
            engines={},
        )

    @staticmethod
    @abstractmethod
    def _per_file_analyzer(bundle: Any, file: Any, task_id: Optional[int] = None, task_reporter: Optional[Any] = None) -> List[Finding]:  # type: ignore
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


def pool_wrapper(
    bundle: DotWiz, runner: Callable, task_id: Optional[int], task_reporter: DictProxy, file: str
) -> List[Finding]:  # pragma: nocover
    result = runner(bundle, file, task_id, task_reporter)
    return result
