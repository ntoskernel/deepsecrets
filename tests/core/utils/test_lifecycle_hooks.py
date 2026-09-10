import pytest

from deepsecrets.core.utils import lifecycle_hooks
from deepsecrets.core.utils.lifecycle_hooks import FileLifecycleHooks
from deepsecrets.core.utils.progress import REPORT_THROTTLING_PERIOD_SECONDS, FileProgress


class CountingReporter(dict):
    def __init__(self):
        super().__init__()
        self.writes = 0

    def __setitem__(self, key, value):
        self.writes += 1
        super().__setitem__(key, value)


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(lifecycle_hooks.time, 'monotonic', fake)
    return fake


def _hooks(reporter):
    progress = FileProgress()
    progress.set_file_size(100)
    progress.add_tokenizer('LexerTokenizer')
    return FileLifecycleHooks(task_id=7, progress=progress, reporter=reporter)


def test_per_token_reports_are_throttled(clock):
    # every report is an IPC round trip to the single Manager process; one per token capped scan throughput
    reporter = CountingReporter()
    hooks = _hooks(reporter)
    hooks.on_start()
    hooks.on_tokenization_finished('LexerTokenizer', 10_000)

    for _ in range(10_000):
        hooks.on_token_processing_start('LexerTokenizer')
        hooks.on_token_processing_end(0)

    assert reporter.writes == 1  # only on_start: no time has passed


def test_throttled_reports_resume_after_the_period(clock):
    reporter = CountingReporter()
    hooks = _hooks(reporter)
    hooks.on_start()
    hooks.on_tokenization_finished('LexerTokenizer', 3)

    clock.now += REPORT_THROTTLING_PERIOD_SECONDS
    hooks.on_token_processing_start('LexerTokenizer')
    hooks.on_token_processing_end(2)  # within the same period: not reported

    assert reporter.writes == 2
    assert reporter[7]['processed'] == 1
    assert reporter[7]['findings'] == 0


def test_tokenization_progress_is_throttled(clock):
    reporter = CountingReporter()
    hooks = _hooks(reporter)
    hooks.on_start()
    for offset in range(100):
        hooks.on_tokenization_progress('LexerTokenizer', offset / 100)

    assert reporter.writes == 1


def test_lifecycle_transitions_always_report(clock):
    # the scan loop waits for the 'finished' write, so it must never be throttled (KI-CLI-05)
    reporter = CountingReporter()
    hooks = _hooks(reporter)
    hooks.on_start()
    hooks.on_tokenization_finished('LexerTokenizer', 5)
    for _ in range(5):
        hooks.on_token_processing_start('LexerTokenizer')
        hooks.on_token_processing_end(1)
    hooks.on_finish()

    assert reporter.writes == 2
    assert reporter[7]['finished'] is True
    assert reporter[7]['processed'] == 5
    assert reporter[7]['findings'] == 5


def test_failure_always_reports(clock):
    reporter = CountingReporter()
    hooks = _hooks(reporter)
    hooks.on_start()
    hooks.on_failure()

    assert reporter.writes == 2
    assert reporter[7]['failure'] is True
    assert reporter[7]['finished'] is True


def test_no_reporter_is_fine(clock):
    hooks = _hooks(None)
    hooks.on_start()
    hooks.on_token_processing_start('LexerTokenizer')
    hooks.on_finish()
    assert hooks.progress.processed_count == 1
