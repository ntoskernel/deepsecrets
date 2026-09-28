"""Regex candidates: typed groups, their own scoring rules, judgement in RegexEngine. Values are synthetic."""

import pytest

from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.helpers.regex_candidate_evaluator import REJECT_AT, RegexCandidateEvaluator
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.regex_candidate import RegexCandidateContext, host_kind
from deepsecrets.core.model.rules.regex import Evidence, GroupType, RegexRule
from deepsecrets.core.model.rules.regex_candidate_scoring import CandidateCondition, RegexCandidateScoringRule
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.rulesets.regex_candidate_scoring import RegexCandidateScoringRulesetBuilder
from deepsecrets.core.utils.fs import get_path_inside_package

PATH = '/repo/src/settings.py'


@pytest.fixture(scope='module')
def candidate_rules():
    return (
        RegexCandidateScoringRulesetBuilder()
        .with_rules_from_file(get_path_inside_package('rules/regex_candidate_scoring_rules.json'))
        .rules
    )


@pytest.fixture(scope='module')
def rules():
    built = RegexRulesetBuilder().with_rules_from_file(get_path_inside_package('rules/regexes.json')).rules
    return {rule.id: rule for rule in built}


def judge(candidate_rules, rule, text, path=PATH):
    match = rule.matches(text)[0]
    context = RegexCandidateContext.from_match(rule, match.match, text[match.start : match.end], path)
    return context, RegexCandidateEvaluator(candidate_rules).evaluate(context)


def test_groups_are_typed_in_match_rules(rules):
    s19, s41, s36 = rules['S19'], rules['S41'], rules['S36']
    assert (s19.group_of(GroupType.USER), s19.group_of(GroupType.VALUE), s19.group_of(GroupType.HOST)) == (1, 2, 3)
    assert (s41.group_of(GroupType.HOST), s41.group_of(GroupType.VALUE)) == (1, 2)
    assert s36.group_of(GroupType.VALUE) == 1 and s36.group_of(GroupType.HOST) is None


def test_a_group_type_is_declared_once():
    with pytest.raises(ValueError):
        RegexRule(id='T', pattern='(a)(b)', match_rules={'1': {'type': 'host'}, '2': {'type': 'host'}})


def test_a_typed_group_needs_no_pattern():
    rule = RegexRule(id='T', pattern='(a)(b)', match_rules={'1': {'type': 'name'}})
    assert rule.match('ab') == [(0, 2)]


def test_the_candidate_reads_its_groups(candidate_rules, rules):
    context, _ = judge(candidate_rules, rules['S19'], 'db = "postgres://app:Tq7XbR2mKp9LvZ4w@db.billing-prod.net/x"')
    assert (context.user, context.value, context.host_kind) == ('app', 'Tq7XbR2mKp9LvZ4w', 'public')


@pytest.mark.parametrize(
    'address, kind',
    [
        ('db.billing-prod.net/x', 'public'),
        ('localhost:5432', 'local'),
        ('db:27017', 'local'),
        ('foobar.com:1234/x', 'placeholder'),
        ('api.example.com', 'placeholder'),
        ('', 'none'),
    ],
)
def test_host_kind(address, kind):
    assert host_kind(address) == kind


def test_a_format_match_keeps_its_confidence_and_is_rejected_only_for_an_unrandom_placeholder(candidate_rules, rules):
    # S36 judges the key body: the 'test' of sk_test_ is the key's mode, not a placeholder word
    _, kept = judge(candidate_rules, rules['S36'], "k = 'sk_test_a1b2c3d4a1b2c3d4e5f6e5f6a1b2c3d4'")
    assert not kept.rejected and kept.confidence is None
    _, rejected = judge(candidate_rules, rules['S36'], "k = 'sk_test_exampleexampleexampleexa'")
    assert rejected.rejected and rejected.reason == 'RC_FORMAT_PLACEHOLDER'


def test_a_shape_match_gets_a_confidence_from_its_value(candidate_rules, rules):
    _, random = judge(candidate_rules, rules['S19'], 'postgres://app:Tq7XbR2mKp9LvZ4w@localhost/x')
    assert not random.rejected and random.confidence == 9
    _, in_tests = judge(
        candidate_rules, rules['S19'], 'postgres://app:Tq7XbR2mKp9LvZ4w@localhost/x', '/repo/tests/a.py'
    )
    assert in_tests.confidence == 8 and in_tests.fired == {'RC_TEST_PATH': None} and in_tests.total == -1


def test_a_word_as_a_password_is_rejected(candidate_rules, rules):
    _, verdict = judge(candidate_rules, rules['S19'], 'postgres://app:sunshine@localhost/x')
    assert verdict.rejected and verdict.reason == 'RC_NATURAL_LANGUAGE' and verdict.confidence == 0
    assert verdict.total == REJECT_AT and verdict.fired == {'RC_NATURAL_LANGUAGE': None}


def test_a_public_host_lowers_the_bar(candidate_rules, rules):
    text = 'postgres://app:{}@{}/x'
    _, public = judge(candidate_rules, rules['S19'], text.format('orangeelephantpillow', 'db.billing-prod.net'))
    _, local = judge(candidate_rules, rules['S19'], text.format('orangeelephantpillow', 'localhost'))
    assert not public.rejected and local.rejected


@pytest.mark.parametrize('host, kept', [('sqlprod.database.windows.net', True), ('localhost', False)])
def test_a_placeholder_word_does_not_count_for_a_public_host(candidate_rules, rules, host, kept):
    text = f'conn = "jdbc:sqlserver://{host}:1433;database=app;user=svc;password=MyPassword#2024;"'
    _, verdict = judge(candidate_rules, rules['S41'], text)
    assert verdict.rejected is not kept


def scan(engine, content, corroborated=False):
    file = File(path=PATH, relative_path='src/settings.py', content=content)
    from deepsecrets.core.model.token import Token

    token = Token(file=file, content=content, span=[0, len(content)])
    return engine.search(token, corroborated=corroborated)


def test_the_engine_drops_a_rejected_candidate_unless_asked(candidate_rules, rules):
    content = 'url = "postgres://app:sunshine@localhost/x"'
    assert scan(RegexEngine(ruleset=[rules['S19']], candidate_rules=candidate_rules), content) == []
    engine = RegexEngine(ruleset=[rules['S19']], candidate_rules=candidate_rules, report_rejected=True)
    [finding] = scan(engine, content)
    assert finding.rejected and finding.rules[0].confidence == 0 and finding.rules[0].is_dynamic_confidence


def test_the_engine_logs_rejections_for_the_tracer(candidate_rules, rules):
    engine = RegexEngine(ruleset=[rules['S19']], candidate_rules=candidate_rules)
    engine.rejected_log = []
    scan(engine, 'url = "postgres://app:sunshine@localhost/x"')
    assert engine.rejected_log[0]['rule'] == 'S19' and engine.rejected_log[0]['reason'] == 'RC_NATURAL_LANGUAGE'


def test_a_match_the_semantic_engine_corroborated_is_not_judged_again(candidate_rules, rules):
    # the whole token is the value of a variable the semantic engine reported: the rule keeps its own confidence
    engine = RegexEngine(ruleset=[rules['S35']], candidate_rules=candidate_rules)
    assert scan(engine, 'AKIAIOSFODNN7EXAMPLE') == []
    [finding] = scan(engine, 'AKIAIOSFODNN7EXAMPLE', corroborated=True)
    assert finding.rules[0].confidence == 10 and not finding.rules[0].is_dynamic_confidence


def test_a_rule_without_an_evidence_class_is_not_judged(candidate_rules):
    custom = RegexRule(id='CUSTOM1', pattern='sunshine')
    [finding] = scan(RegexEngine(ruleset=[custom], candidate_rules=candidate_rules), 'x = "sunshine"')
    assert not finding.rejected and finding.rules[0].confidence == 10


def test_merging_keeps_one_rule_per_id():
    dynamic = Rule(id='S35', confidence=7, is_dynamic_confidence=True)
    static = Rule(id='S35', confidence=10)
    # a corroborated (static) copy beats a judged (dynamic) one
    a = Finding(detection='x', start_offset=0, end_offset=1, rules=[dynamic])
    a.merge(Finding(detection='x', start_offset=0, end_offset=1, rules=[static]))
    assert a.rules == [static] and a.rules[0].confidence == 10
    # between two dynamic copies the first seen stays, as before
    low, high = Rule(id='S105', confidence=4, is_dynamic_confidence=True), Rule(
        id='S105', confidence=9, is_dynamic_confidence=True
    )
    b = Finding(detection='x', start_offset=0, end_offset=1, rules=[low])
    b.merge(Finding(detection='x', start_offset=0, end_offset=1, rules=[high]))
    assert b.rules[0].confidence == 4
    # a kept finding's copy beats a rejected candidate's, and the merge is rejected only when both are
    rejected = Finding(
        detection='x',
        start_offset=0,
        end_offset=1,
        rules=[Rule(id='S19', confidence=0, is_dynamic_confidence=True)],
        rejected=True,
    )
    rejected.merge(
        Finding(
            detection='x',
            start_offset=0,
            end_offset=1,
            rules=[Rule(id='S19', confidence=6, is_dynamic_confidence=True)],
        )
    )
    assert rejected.rules[0].confidence == 6 and not rejected.rejected


def test_a_random_value_buys_a_warning_back_through_a_case(candidate_rules, rules):
    # a random value keeps the match but not its corroboration: -8 + 4 = -4, above the rejection line
    context, verdict = judge(candidate_rules, rules['S36'], "k = 'sk_live_Xk9pQ2mZ7rT4vW8yB3nL6hJexample'")
    assert not verdict.rejected and verdict.total == -4
    assert verdict.fired == {'RC_FORMAT_PLACEHOLDER': 'random enough to be a secret anyway'}


def test_a_public_host_cancels_a_placeholder_word(candidate_rules, rules):
    text = 'conn = "jdbc:sqlserver://sqlprod.database.windows.net:1433;database=app;password=MyPassword#2024;"'
    _, verdict = judge(candidate_rules, rules['S41'], text)
    assert verdict.fired['RC_PLACEHOLDER'] == 'a public host: a weak password, not an example'


def rule(**fields):
    fields.setdefault('id', 'T')
    return RegexCandidateScoringRule(target='VALUE', pattern='.', **fields)


def test_only_the_first_case_that_holds_counts():
    context = RegexCandidateContext(name='', value='Tq7XbR2mKp9LvZ4w', filepath=PATH, evidence='shape')
    both = rule(
        score=-8,
        cases=[
            {'name': 'first', 'if': [{'target': 'VALUE_ENTROPY', 'method': '>', 'threshold': 1}], 'score': 4},
            {'name': 'second', 'if': [{'target': 'VALUE_LENGTH', 'method': '>', 'threshold': 1}], 'score': 8},
        ],
    )
    verdict = RegexCandidateEvaluator([both]).evaluate(context)
    assert verdict.total == -4 and verdict.fired == {'T': 'first'}


def test_rules_add_up_and_reject_at_the_line():
    context = RegexCandidateContext(name='', value='Tq7XbR2mKp9LvZ4w', filepath=PATH, evidence='shape')
    four = [rule(id=f'T{i}', score=-4) for i in range(2)]
    assert RegexCandidateEvaluator(four[:1]).evaluate(context).rejected is False
    assert RegexCandidateEvaluator(four).evaluate(context).rejected is True


def test_categorical_fields_are_compared_by_equality():
    context = RegexCandidateContext(name='', value='x', filepath=PATH, evidence='shape', host='db:5432')
    assert CandidateCondition(target='EVIDENCE', equals='shape').holds(context)
    assert not CandidateCondition(target='EVIDENCE', equals='shap').holds(context)
    assert CandidateCondition(**{'target': 'HOST_KIND', 'in': ['local', 'none']}).holds(context)


@pytest.mark.parametrize(
    'fields',
    [{}, {'equals': 'shape', 'pattern': 'x'}, {'method': '~', 'threshold': 1}, {'method': '>'}],
)
def test_a_condition_takes_exactly_one_form(fields):
    with pytest.raises(ValueError):
        CandidateCondition(target='EVIDENCE', **fields)


def test_the_evidence_label_is_format_or_shape():
    assert RegexRule(id='T', pattern='x', evidence='shape').evidence == Evidence.SHAPE
    with pytest.raises(ValueError):
        RegexRule(id='T', pattern='x', evidence='context')


def test_only_the_value_group_declares_an_encoding():
    with pytest.raises(ValueError):
        RegexRule(id='T', pattern='(a)(b)', match_rules={'1': {'type': 'host', 'encoding': 'base64'}})
    assert RegexRule(id='T', pattern='(a)', match_rules={'1': {'type': 'value', 'encoding': 'hex'}}).encoding_of_value()


def pem(body_lines):
    return '-----BEGIN RSA PRIVATE KEY-----\n' + '\n'.join(body_lines) + '\n-----END RSA PRIVATE KEY-----'


def test_a_key_rule_judges_the_body_not_the_armour(candidate_rules, rules):
    import base64
    import random
    import textwrap

    generator = random.Random(3)
    body = base64.b64encode(bytes(generator.randrange(256) for _ in range(900))).decode()
    context, kept = judge(candidate_rules, rules['S1'], pem(textwrap.wrap(body, 64)))
    # the armour's PRIVATE no longer reaches the placeholder rule: the value is the body
    assert context.value == body and context.encoding == 'base64' and not kept.rejected and kept.fired == {}


@pytest.mark.parametrize(
    'lines, reason',
    [
        (['MIIEpAIBAAKCAQEA...', '...your private key goes here, one line per 64 characters...'], 'RC_NOT_ENCODED'),
        (['A' * 64] * 4, 'RC_LONG_NOT_RANDOM'),
        (['MIIEpAIBAAKCAQEA' + 'A' * 48, 'A' * 16], 'RC_NOT_RANDOM'),
    ],
    ids=['ellipsis', 'one repeated character, long', 'mostly one character, short'],
)
def test_a_key_body_that_is_not_key_material_is_rejected(candidate_rules, rules, lines, reason):
    _, verdict = judge(candidate_rules, rules['S1'], pem(lines))
    assert verdict.rejected and verdict.reason == reason


def test_an_aws_key_id_is_base32(candidate_rules, rules):
    context, verdict = judge(candidate_rules, rules['S35'], 'id = "AKIA0000000000000000"')
    assert (context.kind, context.encoding) == ('AKIA', 'base32')
    assert verdict.rejected and verdict.reason == 'RC_NOT_ENCODED'


def test_a_wif_key_needs_its_checksum(candidate_rules, rules):
    import hashlib

    from deepsecrets.core.helpers.encoding import BASE58

    raw = b'\x80' + hashlib.sha256(b'a synthetic key').digest()
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    number, key = int.from_bytes(raw, 'big'), ''
    while number:
        number, digit = divmod(number, 58)
        key = BASE58[digit] + key
    context, kept = judge(candidate_rules, rules['S37'], f'wif = "{key}"')
    assert context.value_checksum == 'valid' and not kept.rejected
    altered = key[:-1] + ('2' if key[-1] != '2' else '3')
    _, rejected = judge(candidate_rules, rules['S37'], f'wif = "{altered}"')
    assert rejected.rejected and rejected.reason == 'RC_BAD_CHECKSUM'


def test_a_placeholder_token_is_far_from_random(candidate_rules, rules):
    _, verdict = judge(candidate_rules, rules['S0'], 'token = "xoxb-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXXXX"')
    assert verdict.rejected and verdict.reason == 'RC_NOT_RANDOM'
    _, kept = judge(candidate_rules, rules['S0'], 'token = "xoxb-123456789012-123456789012-Zk3pQ9rT2mX7vB1nW4yL8hJd"')
    assert not kept.rejected


def test_a_comparison_on_a_text_field_is_refused_when_the_rules_load():
    # at scan time it would raise TypeError ('<' between str and float) and abandon the rest of the file
    with pytest.raises(ValueError, match='numeric field'):
        RegexCandidateScoringRule(id='X', target='VALUE', method='<', threshold=3, score=-8)
    RegexCandidateScoringRule(id='X', target='VALUE_LENGTH', method='<', threshold=3, score=-8)


@pytest.mark.parametrize('report_rejected', [False, True])
def test_an_empty_match_is_never_reported(candidate_rules, rules, report_rejected):
    # S41's password group can match nothing (password=;): 2.1 reported an empty detection, 2.2 rejected it
    engine = RegexEngine(ruleset=[rules['S41']], candidate_rules=candidate_rules, report_rejected=report_rejected)
    assert scan(engine, 'conn = "sqlserver://db.example.org;user=sa;password=;"') == []
    assert scan(RegexEngine(ruleset=[rules['S41']]), 'conn = "sqlserver://db.example.org;user=sa;password=;"') == []
