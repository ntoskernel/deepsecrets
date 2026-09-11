import hashlib
import json
from typing import List

import pytest

from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.rules.hashed_secret import HashedSecretRule
from deepsecrets.core.model.rules.hashing import HashingAlgorithm
from deepsecrets.core.model.token import Token
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.tokenizers.lexer import LexerTokenizer

SECRET = 'hunter2hunter2'


def _rule(algorithm: str, payload: str, name: str) -> HashedSecretRule:
    digest = hashlib.new(algorithm, payload.encode()).hexdigest()
    return HashedSecretRule(
        id=None, name=name, hashed_val=digest, algorithm=algorithm, token_length=len(SECRET), confidence=10
    )


def _secret_token() -> Token:
    file = File(path=None, content=f'x = "{SECRET}"\n', extension='py')
    return Token(file=file, content=SECRET, span=[5, 5 + len(SECRET)])


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


@pytest.mark.parametrize('decoy_algorithm, real_algorithm', [('sha1', 'sha256'), ('sha512', 'sha1')])
def test_mixed_algorithms_for_same_length(decoy_algorithm, real_algorithm):
    # a rule with another algorithm for the same token length used to blind the later rule
    decoy = _rule(decoy_algorithm, 'someotherpass', 'decoy')
    real = _rule(real_algorithm, SECRET, 'real')

    findings = HashedSecretEngine(ruleset=[decoy, real]).search(_secret_token())

    assert len(findings) == 1
    assert findings[0].rules[0].name == 'real'


def test_hash_is_cached_per_algorithm():
    token = _secret_token()
    sha1 = token.calculate_hashed_value(HashingAlgorithm.SHA_1)
    sha256 = token.calculate_hashed_value(HashingAlgorithm.SHA_256)

    assert sha1 == hashlib.sha1(SECRET.encode()).hexdigest()
    assert sha256 == hashlib.sha256(SECRET.encode()).hexdigest()
    assert token.calculate_hashed_value(HashingAlgorithm.SHA_1) == sha1


def test_builder_merges_rules_from_several_files(tmp_path, hashed_secrets_fixture_file_location):
    extra_hash = hashlib.sha256(SECRET.encode()).hexdigest()
    extra = tmp_path / 'extra_hashes.json'
    extra.write_text(json.dumps([{'name': 'Extra', 'hash': extra_hash, 'length': len(SECRET), 'algorithm': 'sha256'}]))

    builder = HashedSecretsRulesetBuilder()
    builder.with_rules_from_file(hashed_secrets_fixture_file_location)
    builder.with_rules_from_file(str(extra))
    # loading the same file again must not duplicate its rules
    builder.with_rules_from_file(str(extra))

    hashes = sorted(rule.hashed_val for rule in builder.rules)
    assert hashes == sorted(['8c535f99d6d0fa55b64af0fae6e3b6829eda413b', 'fakjsdfiudsajfndsjkafka', extra_hash])
