from typing import Optional
from deepsecrets.core.model.token import Token
from deepsecrets.core.utils.progress import FileProgress, Progress
from multiprocessing.managers import DictProxy


class LifecycleHooks:
    progress: Progress
    reporter: DictProxy
    task_id: int

    def __init__(self, task_id: int, progress: Progress, reporter: DictProxy) -> None:
        self.task_id = task_id
        self.progress = progress
        self.reporter = reporter

    def on_start(self):
        self.progress.on_start()
        self._report()

    def on_failure(self, child_report: Optional[dict] = None):
        self.progress.on_failure()
        self._report(child_report)

    def on_finish(self, child_report: Optional[dict] = None):
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

    def on_token_processing_start(self, token: Token):
        self.progress.on_token_processing_start()
        self._report()

    def on_token_processing_end(self, findings_count: int):
        self.progress.add_findings_count(findings_count)
        self._report()
