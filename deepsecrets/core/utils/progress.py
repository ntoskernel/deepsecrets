from typing import Optional


class Progress:

    started: bool
    finished: bool
    failure: bool

    def __init__(self) -> None:
        self.started = False
        self.finished = False
        self.failure = False

    def on_start(self):
        self.started = True

    def on_finish(self):
        self.finished = True
        self.started = False

    def on_failure(self):
        self.failure = True
        self.finished = True

    def report(self, child_report: Optional[dict] = None):
        child_report = child_report if child_report is not None else dict()

        merged = dict(child_report) | {
            'started': self.started,
            'failure': self.failure,
            'finished': self.finished,
        }
        return merged


class FileProgress(Progress):
    total_tokens: int
    processed_count: int
    findings: int
    file_size: str

    tokenizers_total: int
    tokenizers_done: int

    def __init__(self, tokenizers_total: int, tokenizers_done: int = 0):
        super().__init__()
        self.total_tokens = 0
        self.processed_count = 0
        self.findings = 0

        self.tokenizers_total = tokenizers_total
        self.tokenizers_done = tokenizers_done

    def on_tokenization_finished(self, token_count: int):
        self.total_tokens += token_count
        self.tokenizers_done += 1

    def on_token_processing_start(self):
        self.processed_count += 1

    def add_findings_count(self, count: int):
        self.findings += count

    def set_file_size(self, file_size: int):
        self.file_size = f'{round(file_size / 1024)} Kb'

    def report(self, child_report: Optional[dict] = None):
        if self.tokenizers_total > 0 and self.tokenizers_done > 0:
            total_tokens = self.total_tokens / (self.tokenizers_done / self.tokenizers_total)
        else:
            total_tokens = self.total_tokens

        return super().report() | {
            'total_tokens': total_tokens,
            'processed': self.processed_count,
            'findings': self.findings,
            'file_size': self.file_size,
        }
