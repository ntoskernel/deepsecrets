import pytest

from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from tests.case_helpers import regex_case, semantic_case, variable_detection_case


@pytest.mark.fixture_file_path('cases/inline_yaml_inside_yaml_inside_markdown.md')
def test_6(file: File):

    findings, tokens, variables = semantic_case(file)
    assert len(variables) == 7
    assert len(findings) == 1


@pytest.mark.fixture_file_path('cases/inline_yaml_inside_yaml.yaml')
def test_7(file: File, lexer_tokenizer: LexerTokenizer):
    vars, _, tokens = variable_detection_case(lexer_tokenizer, file)
    assert len(vars) == 7


@pytest.mark.fixture_file_path('cases/code_in_markdown_with_lang_labels.md')
def test_8(file: File, lexer_tokenizer: LexerTokenizer):
    vars, _, tokens = variable_detection_case(lexer_tokenizer, file)
    assert 1 == 1


@pytest.mark.fixture_file_path('cases/tricky_secrets.min.js')
def test_9(file: File):

    findings, tokens, variables = semantic_case(file)
    assert len(findings) == 4


@pytest.mark.fixture_file_path('1.pem')
def test_10(file: File, full_content_tokenizer: FullContentTokenizer, regex_engine: RegexEngine):
    findings, tokens, variables = regex_case(
        tokenizer=full_content_tokenizer,
        engine=regex_engine,
        file=file,
    )
    assert 1 == 1
