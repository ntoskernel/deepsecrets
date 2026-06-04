from typing import List

import pytest

from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.rules.hashed_secret import HashedSecretRule
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.lexer import LexerTokenizer


def test_ruleset_init_success(hashed_secrets_engine: HashedSecretEngine):
    rules = hashed_secrets_engine.ruleset

    assert rules[0] == rules[0]
    assert rules[1] == rules[1]
    assert rules[1] != rules[0]


@pytest.mark.fixture_file_path('1.py')
def test_engine_works(file: File, hashed_secrets_engine: HashedSecretEngine):
    findings: List[Finding] = []
    tokens: List[Token] = LexerTokenizer(deep_token_inspection=True).tokenize(file)
    for token in tokens:
        findings.extend(hashed_secrets_engine.search(token))

    assert len(findings) == 1
    assert isinstance(findings[0].rules[0], HashedSecretRule)
    assert findings[0].rules[0].hashed_val == '8c535f99d6d0fa55b64af0fae6e3b6829eda413b'
