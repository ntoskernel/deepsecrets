"""Labelled cases for the variable-scoring rules (`deepsecrets/rules/variable_scoring_rules.json`).

Each case is the verdict a well-balanced ruleset should give for one variable. Cases the current
rules get wrong carry `known_imbalance(...)`, a strict xfail: when a rebalancing fixes one, it turns
into XPASS and fails the run until the marker is removed. That keeps the table honest in both
directions.

Values are synthetic. Never paste a real secret, including one from SecretBench, into this file.
"""

import pytest

from deepsecrets.core.helpers.variable_evaluator import VariableEvaluator
from deepsecrets.core.model.semantic import Context


def known_imbalance(reason: str):
    return pytest.mark.xfail(strict=True, reason=reason)


CODE = '/repo/src/settings.py'
TESTS = '/repo/tests/test_client.py'

HEX_40 = '9c1f4e7a2b8d6035e1a47c9b0f3d82e6a5c71b40'
HEX_32 = 'e3b8a1f9c4d72605b9e18a3fc2d4706b'
B64_40 = 'q8Lk3VzP0mXw7Rt2Yb9NcF4sHd6JgA1eUo5KiM3T'
ALNUM_24 = 'Tq7XbR2mKp9LvZ4wNc8FjD3s'
LOWER_20 = 'qzkvhtrwpxmbjgnfdlsc'
MIXED_LETTERS_16 = 'QzKvHtRwPxMbJgNf'
B64URL_DASH = '-Hk3vQ9ZpL2mXw7RtYb4NcF8'
B64URL_UNDERSCORE = '_Hk3vQ9ZpL2mXw7RtYb4NcF8'
PASSWORD_RANDOM = 'T7r$kq92LmZx'


DANGEROUS = [
    # password-class names
    pytest.param('password', PASSWORD_RANDOM, CODE, id='password-random'),
    pytest.param('db_password', 'vH3!kL9qZ2pW', CODE, id='db_password-random'),
    pytest.param('DB_PWD', '9fKq2LmZ8xRw', CODE, id='DB_PWD-random'),
    pytest.param('smtp_passwd', 'Xk9mQ2vLp4Rt', CODE, id='smtp_passwd-random'),
    pytest.param('password', PASSWORD_RANDOM, TESTS, id='password-random-in-tests-dir'),
    pytest.param('password', 'adminadmin', CODE, id='password-word-value'),
    pytest.param('db_password', 'sunshine', CODE, id='db_password-word-value'),
    # api / auth / secret names across value alphabets
    pytest.param('api_key', HEX_40, CODE, id='api_key-hex40'),
    pytest.param('api_key', B64_40, CODE, id='api_key-b64'),
    pytest.param('client_secret', ALNUM_24, CODE, id='client_secret-alnum24'),
    pytest.param('auth_token', HEX_32, CODE, id='auth_token-hex32'),
    pytest.param('secret_key', B64_40, TESTS, id='secret_key-b64-in-tests-dir'),
    pytest.param('private_key', HEX_40 + HEX_32, CODE, id='private_key-hex72'),
    pytest.param('api_key', LOWER_20, CODE, id='api_key-random-lowercase'),
    pytest.param(
        'client_secret',
        LOWER_20,
        CODE,
        id='client_secret-random-lowercase',
        marks=known_imbalance('naturalness scores random letters-only strings as natural language (-50 > +30)'),
    ),
    pytest.param(
        'secret',
        MIXED_LETTERS_16,
        CODE,
        id='secret-random-mixedcase-letters',
        marks=known_imbalance('naturalness scores random letters-only strings as natural language (-50 > +30)'),
    ),
    pytest.param('access_token', B64URL_DASH, CODE, id='access_token-b64url-leading-dash'),
    pytest.param('access_token', B64URL_UNDERSCORE, CODE, id='access_token-b64url-leading-underscore'),
    # vendor-prefixed key and token names
    pytest.param('sendgrid_key', ALNUM_24, CODE, id='sendgrid_key'),
    pytest.param('mixpanel_token', HEX_32, CODE, id='mixpanel_token'),
    pytest.param('twilio_auth_token', HEX_32, CODE, id='twilio_auth_token'),
    pytest.param('lastfm_api_key', HEX_32, CODE, id='lastfm_api_key'),
    pytest.param('openWeatherApiKey', HEX_32, CODE, id='openWeatherApiKey'),
    pytest.param('security_key', ALNUM_24, CODE, id='security_key'),
    pytest.param('algolia_key', HEX_32, CODE, id='algolia_key'),
    pytest.param(
        'datadog_key',
        HEX_32,
        CODE,
        id='datadog_key',
        marks=known_imbalance('FULLNAME_REDFLAGS matches "data" inside "datadog"'),
    ),
    pytest.param('open_ai_key', ALNUM_24, CODE, id='open_ai_key'),
    pytest.param('LastFMAPIKey', HEX_32, CODE, id='LastFMAPIKey'),
    pytest.param('securityToken', ALNUM_24, CODE, id='securityToken'),
    pytest.param('strSecret1', ALNUM_24, CODE, id='strSecret1-hungarian-prefix'),
    pytest.param('signing_key', B64_40, CODE, id='signing_key'),
    # names without any positive rule
    pytest.param(
        'credentials',
        B64_40,
        CODE,
        id='credentials',
        marks=known_imbalance('no positive name rule matches "credentials"'),
    ),
    # values from the original fixtures
    pytest.param('db_pass', 'nacc6opq', CODE, id='db_pass-short-random'),
    pytest.param('smtp_pass', PASSWORD_RANDOM, CODE, id='smtp_pass-random'),
    pytest.param('SLOBS_STREAM_KEY', 'live_137546668_M4qFRbcNbYwEzVP5Ljgrexq2lZ5BX6', CODE, id='stream_key'),
]


NOT_DANGEROUS = [
    # placeholders and references
    pytest.param('password', 'changeme', CODE, id='password-changeme'),
    pytest.param('password', '<your-password>', CODE, id='password-angle-placeholder'),
    pytest.param('api_key', '${API_KEY}', CODE, id='api_key-env-reference'),
    pytest.param('token', '%TOKEN%', CODE, id='token-percent-placeholder'),
    pytest.param('api_key', 'your_api_key_here', CODE, id='api_key-your-here'),
    pytest.param('password', '********', CODE, id='password-asterisks'),
    pytest.param('secret', 'xxxxxxxxxxxx', CODE, id='secret-xxx'),
    pytest.param('password', 'password', CODE, id='password-password'),
    pytest.param('secret_key', 'undefined', CODE, id='secret_key-undefined'),
    pytest.param('token', 'null', CODE, id='token-null'),
    pytest.param('api_key', 'abc', CODE, id='api_key-too-short'),
    # non-secret names with random-looking values
    pytest.param('cache_key', HEX_32, CODE, id='cache_key-hex'),
    pytest.param('public_key', B64_40, CODE, id='public_key-b64'),
    pytest.param('session_id', HEX_32, CODE, id='session_id-hex'),
    pytest.param('key_id', ALNUM_24, CODE, id='key_id-alnum'),
    pytest.param('commit_sha', HEX_40, CODE, id='commit_sha-hex40'),
    pytest.param('checksum', HEX_32, CODE, id='checksum-hex32'),
    pytest.param('color', '#1f2a3b', CODE, id='color-hex'),
    # secret-ish names with non-secret values
    pytest.param('password_policy', 'strict', CODE, id='password_policy-word'),
    pytest.param('token_url', 'https://auth.example.com/oauth/token', CODE, id='token_url-url'),
    pytest.param('password_field', 'userpassword', CODE, id='password_field-word'),
    pytest.param('token_type', 'bearer', CODE, id='token_type-bearer'),
    pytest.param('secret_name', 'database', CODE, id='secret_name-word'),
    pytest.param('api_key_header', 'X-API-Key', CODE, id='api_key_header'),
    pytest.param('output_token', 'PolicyDescriptions', CODE, id='output_token-camel-words'),
    pytest.param('result_key', 'GameSessions', CODE, id='result_key-camel-words'),
    pytest.param('key', 'ArrowUp', CODE, id='key-keyboard-name'),
    pytest.param('hashed_password', '$2b$12$' + B64_40[:22] + ALNUM_24[:9], CODE, id='hashed_password-bcrypt'),
    pytest.param('hashed_secret', HEX_40, CODE, id='hashed_secret-detect-secrets-baseline'),
    # a secret word followed by a non-secret one: the last word says what the value is
    pytest.param('oauth-client-id', ALNUM_24, CODE, id='oauth-client-id'),
    pytest.param('oauth-client-id', ALNUM_24, TESTS, id='oauth-client-id-in-tests-dir'),
    pytest.param('secret_id', ALNUM_24, CODE, id='secret_id'),
    pytest.param('api_key_id', ALNUM_24, CODE, id='api_key_id'),
    pytest.param('password-path', '/run/secrets/db_password', CODE, id='password-path-path'),
    pytest.param('password-path', ALNUM_24, CODE, id='password-path-random'),
    pytest.param('oauth-redirect-uri', ALNUM_24, CODE, id='oauth-redirect-uri'),
    pytest.param('password_length', ALNUM_24, CODE, id='password_length'),
    pytest.param('password_hint', ALNUM_24, CODE, id='password_hint'),
    pytest.param('password_file', ALNUM_24, CODE, id='password_file'),
    pytest.param('secret_arn', ALNUM_24, CODE, id='secret_arn'),
    pytest.param('pwd_dir', ALNUM_24, CODE, id='pwd_dir'),
    pytest.param('token_expiry', ALNUM_24, CODE, id='token_expiry'),
]


@pytest.mark.parametrize('name, value, filepath', DANGEROUS)
def test_dangerous(variable_scoring_rules, name, value, filepath):
    result = VariableEvaluator(variable_scoring_rules).evaluate(Context(name=name, value=value, filepath=filepath))
    assert result.is_dangerous is True, result


@pytest.mark.parametrize('name, value, filepath', NOT_DANGEROUS)
def test_not_dangerous(variable_scoring_rules, name, value, filepath):
    result = VariableEvaluator(variable_scoring_rules).evaluate(Context(name=name, value=value, filepath=filepath))
    assert result.is_dangerous is False, result


@pytest.mark.parametrize(
    'name, low_entropy_value, high_entropy_value',
    [
        pytest.param('password', '11112222ab', 'xK9mQ2vLpq4R', id='password'),
        pytest.param('api_key', 'aaaabbbbcccc1', HEX_40, id='api_key'),
        pytest.param('client_secret', 'abababab12', HEX_32, id='client_secret'),
    ],
)
def test_confidence_does_not_drop_with_entropy(variable_scoring_rules, name, low_entropy_value, high_entropy_value):
    evaluator = VariableEvaluator(variable_scoring_rules)
    low = evaluator.evaluate(Context(name=name, value=low_entropy_value, filepath=CODE))
    high = evaluator.evaluate(Context(name=name, value=high_entropy_value, filepath=CODE))
    assert low.is_dangerous and high.is_dangerous
    assert high.export_confidence >= low.export_confidence, (low, high)


@pytest.mark.parametrize('name', ['sign_key', 'signing_key', 'signingKey', 'slack_signing_secret', 'signingToken'])
def test_signing_names_are_very_high_confidence(variable_scoring_rules, name):
    # "signing" must count like "sign": signing_key is as strong a name as sign_key
    result = VariableEvaluator(variable_scoring_rules).evaluate(Context(name=name, value=B64_40, filepath=CODE))
    assert result.is_dangerous is True, result
    assert result.export_confidence >= 9, result


@pytest.mark.parametrize(
    'name, value, filepath',
    [
        pytest.param('password', 'adminadmin', CODE, id='password'),
        pytest.param('db_password', 'sunshine', CODE, id='db_password'),
        pytest.param('password', 'adminadmin', TESTS, id='password-in-tests-dir'),
    ],
)
def test_word_valued_password_is_reported_at_low_confidence(variable_scoring_rules, name, value, filepath):
    # weak and default passwords are dictionary words: report them, but in the LOW SARIF tier (< 3)
    result = VariableEvaluator(variable_scoring_rules).evaluate(Context(name=name, value=value, filepath=filepath))
    assert result.is_dangerous is True, result
    assert result.export_confidence < 3, result
