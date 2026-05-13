import pytest

from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.utils.file_analyzer import FileAnalyzer


@pytest.fixture(scope='module')
def file_toml_1():
    path = 'tests/fixtures/1.toml'
    return File(path=path, relative_path=path)


def test_file_analyzer(file_toml_1):
    file_analyzer = FileAnalyzer(file_toml_1)

    lex = LexerTokenizer(deep_token_inspection=True)
    semantic_engine = SemanticEngine(subengine=None)
    file_analyzer.add_engine(engine=semantic_engine, tokenizers=[lex])

    findings = file_analyzer.process()
    assert findings is not None


def test_progress_reporter_is_batched(file_toml_1, monkeypatch):
    import deepsecrets.core.utils.file_analyzer as fa_module

    monkeypatch.setattr(fa_module, 'PROGRESS_BATCH_SIZE', 8)

    file_analyzer = FileAnalyzer(file_toml_1)
    lex = LexerTokenizer(deep_token_inspection=True)
    semantic_engine = SemanticEngine(subengine=None)
    file_analyzer.add_engine(engine=semantic_engine, tokenizers=[lex])

    calls = []

    class FakeReporter(dict):
        def __setitem__(self, key, value):
            calls.append(dict(value))
            super().__setitem__(key, value)

    file_analyzer.attach_global_task_reporter(task_reporter=FakeReporter(), task_id='t1')
    file_analyzer.process()

    total_tokens = file_analyzer.progress.total_tokens
    # Sanity: fixture must produce enough tokens to cross the batch threshold multiple times.
    assert total_tokens // 8 >= 2, f'fixture too small to exercise batching ({total_tokens} tokens)'
    # Lower bound proves batching fires; upper bound proves we're not still reporting per-token.
    assert len(calls) >= 2
    assert len(calls) <= max(4, total_tokens // 8 + 4)
