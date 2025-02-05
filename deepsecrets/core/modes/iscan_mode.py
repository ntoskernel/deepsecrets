import logging
from multiprocessing.pool import AsyncResult
import regex as re

from multiprocessing import Manager, get_context
from multiprocessing.managers import DictProxy
import os
from abc import abstractmethod
from datetime import datetime
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
from deepsecrets.core.utils.log import build_logger

from rich.progress import Progress as ProgressBar


class ScanMode:
    config: Config
    filepaths: List[str]
    path_exclusion_rules: List[ExcludePathRule] = []
    file_analyzer: FileAnalyzer
    pool_engine: Type
    rulesets: Dict[str, List]
    engines_enabled: Dict[Type, bool]

    task_reporter: DictProxy
    progress_bar: ProgressBar
    jobs: List[AsyncResult]


    def __init__(self, config: Config, pool_engine: Optional[Any] = None) -> None:
        console.print(f'[*] Looking for applicable files...')
        console.line()
        if pool_engine is None:
            self.pool_engine = get_context(config.mp_context).Pool
        else:
            self.pool_engine = pool_engine

        m = Manager()
        self.task_reporter = m.dict({})
        self.progress_bar = None

        self.config = config
        self.jobs = []

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
    

    def refresh_progress_bar(self, overall_progress_task, n_finished, final=False):
        if self.task_reporter is None:
            return
        
        total_findings = 0
        for task_id, current_state in self.task_reporter.items():
            total = current_state.get('total_tokens')
            processed = current_state.get('processed')
            started = current_state.get('started')
            finished = current_state.get('finished')
            visible = started is True and finished is False
            findings = current_state.get('findings')
            total_findings += findings
            # update the progress bar for this task:
            self.progress_bar.update(
                task_id,
                completed=processed,
                total=total,
                visible=visible if not final else False,
                findings=f'FINDINGS: {findings}'
            )
        self.progress_bar.update(
            overall_progress_task,
            completed=n_finished,
            total=len(self.jobs),
            findings=f'RAW FINDINGS: {total_findings}'
        )

    def run(self) -> List[Finding]:
        final: List[Finding] = []
        bundle = self.analyzer_bundle()
        proc_count = self._get_process_count_for_runner()
        if proc_count == 0:
            return final
        
        if self.progress_bar is not None:
            overall_progress_task = self.progress_bar.add_task("[green bold]OVERALL PROGRESS", visible=True, findings='RAW FINDINGS: 0')

        if PROFILER_ON:
            for file in self.filepaths:
                task_id = self.progress_bar.add_task(file, findings='FINDINGS: 0')
                final.extend(self._per_file_analyzer(file=file, bundle=bundle, task_id=task_id, task_reporter=self.task_reporter))
        else:
            with self.pool_engine(processes=proc_count) as pool:
                for file in self.filepaths:
                    task_id = self.progress_bar.add_task(file, findings='FINDINGS: 0', visible=False)
                    # runnable = partial(pool_wrapper, bundle, self._per_file_analyzer, self.task_reporter)
                    self.jobs.append(
                        pool.apply_async(
                            pool_wrapper,
                            (bundle,
                            self._per_file_analyzer,
                            task_id,
                            self.task_reporter,
                            file),
                        )
                    )
                
                while (n_finished := sum([job.ready() for job in self.jobs])) < len(self.jobs):
                    self.refresh_progress_bar(overall_progress_task, n_finished)

        # final refresh
        self.refresh_progress_bar(overall_progress_task, 100, final=True)
        self.progress_bar.stop()

        for job_result in self.jobs:
            file_findings = job_result.get()
            if file_findings is None or len(file_findings) == 0:
                continue
            final.extend(file_findings)
        
        console.line()
        console.print(f'[*] Merging similar findings..')
        fin = FindingMerger(final).merge()

        console.print(f'[*] Filtering predefined false Findings..')
        fin = self.filter_false_positives(fin)
        return fin

    def _get_files_list(self) -> List[str]:
        flist = []
        if not self.path_exclusion_rules:
            excl_paths_builder = ExcludedPathsBuilder()
            for path in self.config.global_exclusion_paths:
                excl_paths_builder.with_rules_from_file(path)

            self.path_exclusion_rules = excl_paths_builder.rules

        for fpath, _, files in os.walk(get_abspath(self.config.workdir_path)):
            for filename in files:
                full_path = os.path.join(fpath, filename)
                rel_path = full_path.replace(f'{self.config.workdir_path}/', '')
                if not self._path_included(rel_path):
                    continue
        
                if not self._size_check(full_path):
                    console.print(f'[bold yellow]:warning: {rel_path}[/bold yellow]: File size exceeds [magenta]--max-file-path[/magenta] of {self.config.max_file_size} bytes and will be [bold]skipped[/bold]')
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
            engines={}
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


def pool_wrapper(bundle: DotWiz, runner: Callable, task_id: Optional[int], task_reporter: DictProxy, file: str) -> List[Finding]:  # pragma: nocover
    logger = build_logger(bundle.logging_level)

    start_ts = datetime.now()
    result = runner(bundle, file, task_id, task_reporter)

    if logger.level == logging.DEBUG:
        pass
        #logger.debug(
        #    f' ✓ [{file}] {(datetime.now() - start_ts).total_seconds()}s elapsed \t {len(result)} potential findings'
        #)
    else:
        pass
        #logger.info(f' ✓ [{file}] \t {len(result)} potential findings')
    return result
