from datetime import datetime
from typing import Optional
from deepsecrets.core.utils.progress import FileProgress, Progress
from multiprocessing.managers import DictProxy


class LifecycleHooks:
    start_ts: datetime
    end_ts: datetime

    progress: Progress
    reporter: DictProxy
    task_id: int

    def __init__(self, task_id: int, progress: Progress, reporter: DictProxy) -> None:
        self.task_id = task_id
        self.progress = progress
        self.reporter = reporter

    def on_start(self):
        self.start_ts = datetime.now()
        self.progress.on_start()
        self._report()

    def on_failure(self, child_report: Optional[dict] = None):
        self.end_ts = datetime.now()
        self.progress.on_failure()
        self._report(child_report)

    def on_finish(self, child_report: Optional[dict] = None):
        self.end_ts = datetime.now()
        self.progress.on_finish()
        self._report(child_report)

    def _report(self, child_report: Optional[dict] = None):
        if self.reporter is None:
            return

        self.reporter[self.task_id] = self.progress.report(child_report)


class JobLifecycleHooks(LifecycleHooks):
    pass


class FileLifecycleHooks(LifecycleHooks):
    progress: FileProgress

    def on_new_tokenizer_added(self, name: str):
        self.progress.add_tokenizer(name)
        self._report()

    def on_token_processing_start(self, name: str):
        self.progress.on_token_processing_start(name=name)
        self._report()

    def on_tokenization_finished(self, name: str, token_count: int):
        self.progress.on_tokenization_finished(name=name, token_count=token_count)

    def on_token_processing_end(self, findings_count: int):
        self.progress.add_findings_count(findings_count)
        self._report()

    def on_tokenization_progress(self, name: str, new_offset: int):
        self.progress.on_tokenization_progress(name, new_offset)
        self._report()
