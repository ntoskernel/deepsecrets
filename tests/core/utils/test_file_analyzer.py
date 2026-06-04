import pytest

from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.utils.file_analyzer import FileAnalyzer


@pytest.mark.fixture_file_path('1.toml')
def test_file_analyzer(file):
    file_analyzer = FileAnalyzer(file)

    lex = LexerTokenizer(deep_token_inspection=True)
    semantic_engine = SemanticEngine(subengine=None)
    file_analyzer.add_engine(engine=semantic_engine, tokenizers=[lex])

    findings = file_analyzer.process()
    assert findings is not None
