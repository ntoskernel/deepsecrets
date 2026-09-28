import pytest

from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.regex import RegexRule
from deepsecrets.core.model.token import Token
from deepsecrets.core.rulesets.regex_candidate_scoring import RegexCandidateScoringRulesetBuilder
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.utils.fs import get_path_inside_package
from tests.case_helpers import regex_case


@pytest.mark.fixture_file_path('regex_checks.txt')
def test_1(file: File, regex_engine: RegexEngine):
    findings, _, _ = regex_case(
        tokenizer=FullContentTokenizer(),
        engine=regex_engine,
        file=file,
    )

    assert len(findings) == 15
    assert findings[0].final_rule.id == 'S0'
    assert findings[1].final_rule.id == 'S0'
    assert findings[2].final_rule.id == 'S1'
    assert findings[3].final_rule.id == 'S2'
    assert findings[4].final_rule.id == 'S3'
    assert findings[5].final_rule.id == 'S4'
    assert findings[6].final_rule.id == 'S5'

    assert findings[7].final_rule.id == 'S19'
    assert findings[7].detection == 'sneakypass'

    assert findings[8].final_rule.id == 'S19'
    assert findings[8].detection == 'ridCNWnbTpavfVuJvWmS'

    # S53 (any-length Stripe keys) matches the two placeholders S36's repeated-character pattern skips; unjudged here,
    # they are rejected as far from random when the candidate rules judge them
    assert [finding.final_rule.id for finding in findings[13:]] == ['S53', 'S53']
    candidate_rules = (
        RegexCandidateScoringRulesetBuilder()
        .with_rules_from_file(get_path_inside_package('rules/regex_candidate_scoring_rules.json'))
        .rules
    )
    judged = RegexEngine(ruleset=regex_engine.ruleset, candidate_rules=candidate_rules)
    judged.rejected_log = []
    regex_case(tokenizer=FullContentTokenizer(), engine=judged, file=file)
    assert [entry['reason'] for entry in judged.rejected_log if entry['rule'] == 'S53'] == ['RC_NOT_RANDOM'] * 2


@pytest.mark.fixture_file_path('extless/radius')
def test_extless(file: File, regex_engine: RegexEngine):
    findings, tokens, variables = regex_case(
        tokenizer=FullContentTokenizer(),
        engine=regex_engine,
        file=file,
    )

    assert len(findings) == 1
    assert findings[0].rules[0].id == 'S28'


@pytest.mark.fixture_file_path('7.go')
def test_go_7(file: File, regex_engine: RegexEngine):
    findings, tokens, variables = regex_case(
        tokenizer=FullContentTokenizer(),
        engine=regex_engine,
        file=file,
    )

    assert len(findings) == 0


@pytest.mark.fixture_file_path('cases/private_keys.txt')
def test_private_keys(file: File, regex_engine: RegexEngine):
    # the two templates in the file (a key inside HTML entities, PGP armour built in minified code) are matched and
    # rejected by the candidate rules as not base64, where a negative pattern on S5 and S26 used to stop the match
    candidate_rules = (
        RegexCandidateScoringRulesetBuilder()
        .with_rules_from_file(get_path_inside_package('rules/regex_candidate_scoring_rules.json'))
        .rules
    )
    engine = RegexEngine(ruleset=regex_engine.ruleset, candidate_rules=candidate_rules)
    findings, tokens, variables = regex_case(
        tokenizer=FullContentTokenizer(),
        engine=engine,
        file=file,
    )

    assert len(findings) == 2

    engine.rejected_log = []
    regex_case(tokenizer=FullContentTokenizer(), engine=engine, file=file)
    assert sorted((entry['rule'], entry['reason']) for entry in engine.rejected_log) == [
        ('S26', 'RC_NOT_ENCODED'),
        ('S5', 'RC_NOT_ENCODED'),
    ]


def _token(content: str) -> Token:
    return Token(file=File(path=None, content=content + '\n'), content=content, span=[0, len(content)])


def test_rule_match_honours_negative_pattern_and_case():
    rule = RegexRule(id='T1', name='test', pattern='secret_[a-z]+', negative_pattern='example')

    assert rule.match(_token('SECRET_abc and secret_def')) == [(0, 10), (15, 25)]
    assert rule.match(_token('secret_abc example')) == []


def test_rule_match_reports_decoded_content_as_whole_token():
    rule = RegexRule(id='T1', name='test', pattern='secret_[a-z]+', case_sensitive=True)
    token = _token('c2VjcmV0X2FiYw==')
    token.uncovered_content.append('secret_abc')

    assert rule.match(token) == [(0, len(token.content))]
    assert rule.match('SECRET_abc') == []


def _service_account(body: str) -> str:
    return (
        '{\n  "type": "service_account",\n  "project_id": "demo-project",\n  "private_key_id": "0123abcd",\n'
        f'  "private_key": "-----BEGIN PRIVATE KEY-----\\n{body}\\n-----END PRIVATE KEY-----\\n",\n'
        '  "client_email": "demo@demo-project.iam.gserviceaccount.com"\n}\n'
    )


def _scan(content: str, regex_engine: RegexEngine):
    file = File(path='service_account.json', relative_path='service_account.json', content=content)
    findings, _, _ = regex_case(tokenizer=FullContentTokenizer(), engine=regex_engine, file=file)
    return findings


def test_s18_names_the_service_account_key_not_the_marker(regex_engine: RegexEngine):
    import base64
    import hashlib

    # a synthetic key body: base64 of a hash chain, split into 64-character lines joined by escaped newlines
    raw = b''.join(hashlib.sha256(bytes([i])).digest() for i in range(40))
    b64 = base64.b64encode(raw).decode()
    body = '\\n'.join(b64[i : i + 64] for i in range(0, len(b64), 64))
    findings = _scan(_service_account(body), regex_engine)

    keys = [f for f in findings if 'S18' in {r.id for r in f.rules}]
    assert len(keys) == 1
    # the same span as S26's generic private-key finding, so the two merge into one finding named by S18
    assert {r.id for r in keys[0].rules} == {'S18', 'S26'}
    assert keys[0].final_rule.id == 'S18'
    assert keys[0].detection.startswith('-BEGIN PRIVATE KEY-----') and keys[0].detection.endswith('END PRIVATE KEY-')


def test_s18_ignores_the_marker_and_placeholder_keys(regex_engine: RegexEngine):
    marker_only = '{"type": "service_account", "client_email": "demo@demo-project.iam.gserviceaccount.com"}\n'
    placeholder = _service_account('MIIEvQIBADAN')  # a library fixture's stub: too short to be a key
    for content in (marker_only, placeholder):
        assert not [f for f in _scan(content, regex_engine) if 'S18' in {r.id for r in f.rules}]


def _random(alphabet: str, length: int, seed: int) -> str:
    import random

    generator = random.Random(seed)
    return ''.join(generator.choice(alphabet) for _ in range(length))


HEX = '0123456789abcdef'
ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789'
MIXED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
PROVIDER_CASES = {
    'S42': ('sonar.login={}', _random(ALNUM, 40, 1)),
    'S43': ('GITHUB_OAUTH_KEY="{}"', _random(HEX, 40, 2)),
    'S44': ("ALGOLIA_ADMIN_KEY: '{}'", _random(ALNUM, 32, 3)),
    'S45': ("const algoliaSearchKey = client('APPID', '{}')", _random(HEX, 32, 4)),
    'S46': ('flickr_api_key = "{}"', _random(ALNUM, 32, 5)),
    'S47': ('bitly access token: {}', _random(HEX, 40, 6)),
    'S48': ('okta.api-token={}', '00' + _random(MIXED, 40, 7)),
    'S49': ('SNYK_TOKEN={}', '1f0c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b'),
    'S50': ('TELEGRAM_TOKEN="{}"', '123456789:AA' + _random(MIXED, 33, 8)),
    'S51': ('bot = Bot("{}")', '987654321:AA' + _random(MIXED, 33, 9)),
    'S52': ('url: {}', 'hooks.slack.com/workflows/' + _random(MIXED, 46, 10)),
    'S53': ('key = "{}"', 'sk_prod_' + _random(MIXED, 16, 11)),
    'S54': ('facebook_app_secret = "{}"', _random(HEX, 32, 12)),
    'S55': ('DROPBOX_APPKEY="{}"', _random(ALNUM, 15, 13)),
    'S56': ('amplitude.init(key, "{}")', _random(HEX, 32, 14)),
}


@pytest.mark.parametrize('rule_id', PROVIDER_CASES)
def test_provider_rules_find_their_tokens(regex_engine: RegexEngine, rule_id: str):
    from deepsecrets.core.helpers.regex_candidate_evaluator import RegexCandidateEvaluator
    from deepsecrets.core.model.regex_candidate import RegexCandidateContext

    template, value = PROVIDER_CASES[rule_id]
    line = template.format(value)
    rule = next(rule for rule in regex_engine.ruleset if rule.id == rule_id)
    [match] = rule.matches(line)
    assert value.endswith(line[match.start : match.end]) or line[match.start : match.end] in value
    candidate_rules = (
        RegexCandidateScoringRulesetBuilder()
        .with_rules_from_file(get_path_inside_package('rules/regex_candidate_scoring_rules.json'))
        .rules
    )
    context = RegexCandidateContext.from_match(
        rule, match.match, line[match.start : match.end], '/repo/src/settings.py'
    )
    assert not RegexCandidateEvaluator(candidate_rules).evaluate(context).rejected
