import pytest

from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from tests.case_helpers import regex_case, semantic_case, variable_detection_case


@pytest.mark.fixture_file_path('cases/inline_yaml_inside_yaml_inside_markdown.md')
def test_inline_yaml_inside_yaml_inside_markdown(file: File):

    findings, tokens, variables = semantic_case(file)
    assert len(variables) == 9
    assert len(findings) == 1


@pytest.mark.fixture_file_path('cases/inline_yaml_inside_yaml.yaml')
def test_inline_yaml_inside_yaml(file: File, lexer_tokenizer: LexerTokenizer):
    vars, _, tokens = variable_detection_case(lexer_tokenizer, file)
    assert len(vars) == 9


@pytest.mark.fixture_file_path('cases/code_in_markdown_with_lang_labels.md')
def test_code_in_markdown_with_lang_labels(file: File, lexer_tokenizer: LexerTokenizer):
    vars, _, tokens = variable_detection_case(lexer_tokenizer, file)
    assert 1 == 1


@pytest.mark.fixture_file_path('cases/tricky_secrets.min.js')
def test_tricky_secrets(file: File):

    findings, _, _ = semantic_case(file)
    assert len(findings) == 5


@pytest.mark.fixture_file_path('1.pem')
def test_1_pem(file: File, full_content_tokenizer: FullContentTokenizer, regex_engine: RegexEngine):
    findings, tokens, variables = regex_case(
        tokenizer=full_content_tokenizer,
        engine=regex_engine,
        file=file,
    )
    assert 1 == 1


@pytest.mark.fixture_file_path('4.json')
def test_4_json(file: File):
    findings, tokens, variables = semantic_case(file)
    assert len(findings) == 1


@pytest.mark.fixture_file_path('cases/js_in_html.html')
def test_5_jsinhtml(file: File):
    findings, tokens, variables = semantic_case(file)
    assert len(findings) == 1


@pytest.mark.fixture_file_path('6.json')
def test_6_json(file: File, full_content_tokenizer: FullContentTokenizer, regex_engine: RegexEngine):
    findings, tokens, variables = regex_case(
        tokenizer=full_content_tokenizer,
        engine=regex_engine,
        file=file,
    )
    assert len(findings) == 1
