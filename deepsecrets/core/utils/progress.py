from datetime import datetime
from typing import Dict, Optional


class Progress:

    started: bool
    finished: bool
    failure: bool
    latest_report: datetime

    def __init__(self) -> None:
        self.started = False
        self.finished = False
        self.failure = False
        self.latest_report = None

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
        self.latest_report = datetime.now()
        return merged


# Minimum interval between per-token progress reports of one file. Every report is a round trip
# to the single Manager process, which serialises all workers; start/finish/failure always report.
REPORT_THROTTLING_PERIOD_SECONDS = 0.2


class FileProgress(Progress):
    total_tokens: int
    processed_count: int
    findings: int
    file_size: int
    file_size_str: str

    tokenizers: Dict[str, Dict]

    def add_tokenizer(self, name: str):
        self.tokenizers[name] = {
            'tokenization_done': False,
            'tokenization_progress_percent': 0,
            'tokens_count': 0,
            'tokens_processed': 0,
        }

    def on_tokenization_progress(self, name: str, new_offset: int):
        self.tokenizers[name]['tokenization_progress_percent'] = new_offset

    def __init__(self):
        super().__init__()
        self.total_tokens = 0
        self.processed_count = 0
        self.findings = 0
        self.tokenizers = {}

    def on_tokenization_finished(self, name: str, token_count: int):
        self.tokenizers[name]['tokenization_done'] = True
        self.tokenizers[name]['tokens_count'] = token_count
        self.total_tokens += token_count

    def on_token_processing_start(self, name: str):
        self.processed_count += 1
        self.tokenizers[name]['tokens_processed'] += 1

    def add_findings_count(self, count: int):
        self.findings += count

    def set_file_size(self, file_size: int):
        self.file_size = file_size
        self.file_size_str = f'{round(file_size / 1024)} Kb'

    def report(self, child_report: Optional[dict] = None):
        # percentages
        # Lexer: 75%             |       FullContent: 5%      | CheapVarSearch: 20%
        # Tokenization: 80%              Tokenization: 5%.    | Tokenization: 70%
        # Search: 20%                    Search: 95%          | Search: 30%

        percentage = 0
        for name, tokenizer_info in self.tokenizers.items():
            tokens_count = tokenizer_info['tokens_count']
            tokenization_done = tokenizer_info['tokenization_done']
            tokenization_progress_percent = tokenizer_info.get('tokenization_progress_percent', 0)
            tokens_processed = tokenizer_info['tokens_processed']

            if name == 'LexerTokenizer':
                if tokenization_done is True:
                    percentage += 76
                    percentage += 14 * (tokens_processed / tokens_count) if tokens_count > 0 else 0
                else:
                    percentage += 76 * tokenization_progress_percent

            if name == 'FullContentTokenizer':
                if tokenization_done is True:
                    percentage += 0.25
                    percentage += 4.75 * (tokens_processed / tokens_count) if tokens_count > 0 else 0
                else:
                    percentage += 0.25 * tokenization_progress_percent

        return {
            'total_tokens': self.total_tokens,
            'percentage': percentage,
            'processed': self.processed_count,
            'findings': self.findings,
            'file_size': self.file_size_str,
        } | super().report()
