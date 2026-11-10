"""Finding tags (2.3): tagging rules, the three tags, merging and pickling. Values are synthetic."""

import pickle

import pytest

from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.helpers.finding_tags import (
    PUBLISHABLE,
    RECORDED_TRAFFIC,
    TAGS,
    TEST_CONTEXT,
    WEAK_PASSWORD,
    apply_path_context,
    in_recorded_traffic,
    in_test_context,
    tag_test_context,
)
from deepsecrets.core.helpers.regex_candidate_evaluator import RegexCandidateEvaluator
from deepsecrets.core.helpers.variable_evaluator import VariableEvaluator
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.regex_candidate import RegexCandidateContext
from deepsecrets.core.model.rules.regex_candidate_scoring import RegexCandidateScoringRule
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.model.rules.variable_scoring import VariableScoringRule
from deepsecrets.core.model.semantic import Context
from deepsecrets.core.model.token import Token
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.rulesets.regex_candidate_scoring import RegexCandidateScoringRulesetBuilder
from deepsecrets.core.rulesets.variable_scoring import VariableScoringRulesetBuilder
from deepsecrets.core.utils.fs import get_path_inside_package
from tests.case_helpers import semantic_case

CODE = '/repo/src/settings.py'
BODY = 'Tq7XbR2mKp9LvZ4wNc8FjD3s'


@pytest.fixture(scope='module')
def variable_rules():
    path = get_path_inside_package('rules/variable_scoring_rules.json')
    return VariableScoringRulesetBuilder().with_rules_from_file(path).rules


@pytest.fixture(scope='module')
def candidate_rules():
    path = get_path_inside_package('rules/regex_candidate_scoring_rules.json')
    return RegexCandidateScoringRulesetBuilder().with_rules_from_file(path).rules


@pytest.fixture(scope='module')
def s36():
    rules = RegexRulesetBuilder().with_rules_from_file(get_path_inside_package('rules/regexes.json')).rules
    return next(rule for rule in rules if rule.id == 'S36')


def test_the_tags_are_three():
    assert TAGS == ('weak-password', 'publishable', 'test-context', 'recorded-traffic')


def test_a_tagging_variable_rule_adds_its_tag_and_no_score(variable_rules):
    tagging = VariableScoringRule(id='T', target='NAME_NORMALIZED', pattern='sitekey', score=0, tag='x-tag')
    context = Context(name='site_key', value=BODY, filepath=CODE)
    without = VariableEvaluator(variable_rules).evaluate(context)
    tagged = VariableEvaluator([*variable_rules, tagging]).evaluate(context)
    assert 'x-tag' in tagged.tags and 'x-tag' not in without.tags
    assert (tagged.is_dangerous, tagged.naming_and_content_score, tagged.export_confidence) == (
        without.is_dangerous,
        without.naming_and_content_score,
        without.export_confidence,
    )


def test_a_tagging_candidate_rule_adds_its_tag_and_no_score(candidate_rules, s36):
    tagging = RegexCandidateScoringRule(id='T', target='MATCH', pattern='^sk_', score=0, tag='x-tag')
    text = f'k = "sk_live_{BODY}"'
    match = s36.matches(text)[0]
    context = RegexCandidateContext.from_match(s36, match.match, text[match.start : match.end], CODE)
    without = RegexCandidateEvaluator(candidate_rules).evaluate(context)
    tagged = RegexCandidateEvaluator([*candidate_rules, tagging]).evaluate(context)
    assert tagged.tags == ['x-tag'] and without.tags == []
    assert (tagged.rejected, tagged.confidence, tagged.total) == (without.rejected, without.confidence, without.total)
    assert tagged.summary()['tags'] == ['x-tag']


def scan_regex(engine, content):
    file = File(path=CODE, relative_path='src/settings.py', content=content)
    return engine.search(Token(file=file, content=content, span=[0, len(content)]))


@pytest.mark.parametrize(
    'value, tagged',
    [
        (f'pk_live_{BODY}', True),
        (f'pk_test_{BODY}', True),
        (f'sk_live_{BODY}', False),
        (f'rk_live_{BODY}', False),
    ],
)
def test_a_stripe_publishable_key_is_tagged_and_a_secret_key_is_not(candidate_rules, s36, value, tagged):
    # S36's value group is the body after pk_live_: RC_TAG_PUBLISHABLE reads the match
    (finding,) = scan_regex(RegexEngine(ruleset=[s36], candidate_rules=candidate_rules), f'key: {value}\n')
    assert finding.rules[0].id == 'S36' and not finding.rejected
    assert finding.tags == ([PUBLISHABLE] if tagged else [])


@pytest.mark.parametrize(
    'name, value, tagged',
    [
        ('RECAPTCHA_SITE_KEY', '6Lc' + BODY + BODY[:13], True),
        ('algolia_search_only_key', 'e3b8a1f9c4d72605b9e18a3fc2d4706b', True),
        ('stripePublishableKey', BODY, True),
        # a name that says secret or private is not publishable
        ('RECAPTCHA_SECRET_KEY', '6Lc' + BODY + BODY[:13], False),
        ('captcha_private_key', BODY, False),
        # by value, whatever the name: a regex match covering this variable is not judged as a candidate
        ('stripe_key', f'pk_live_{BODY}', True),
        ('mapbox_token', 'pk.eyJ1IjoiZXhhbXBsZSIsImEiOiJjazEyMyJ9.' + BODY, True),
        ('stripe_key', f'sk_live_{BODY}', False),
        ('api_key', BODY, False),
    ],
)
def test_publishable_names_and_values_tag_a_variable(variable_rules, name, value, tagged):
    result = VariableEvaluator(variable_rules).evaluate(Context(name=name, value=value, filepath=CODE))
    assert (PUBLISHABLE in result.tags) is tagged, result


def test_the_semantic_engine_copies_the_tags_and_tags_s106_a_weak_password(tmp_path):
    path = tmp_path / 'settings.py'
    path.write_text(
        'password = "nacc6opq"\n'
        f'recaptcha_site_key = "6Lc{BODY}{BODY[:13]}"\n'
        f'stripe_key = "pk_live_{BODY}"\n'
        f'refresh_token = "{BODY}"\n'
    )
    findings, _, _ = semantic_case(File(path=str(path), relative_path='settings.py'))
    tags = {f.internal_score['var']: (f.final_rule.id, f.tags) for f in findings}
    assert tags['password'] == ('S106', [WEAK_PASSWORD])
    assert tags['recaptcha_site_key'] == ('S105', [PUBLISHABLE])
    assert tags['stripe_key'] == ('S105', [PUBLISHABLE])
    assert tags['refresh_token'] == ('S105', [])


def test_tags_change_nothing_but_the_tags(variable_rules, tmp_path):
    # the same file with and without the tagging rules: the same findings, rules and confidences
    path = tmp_path / 'settings.py'
    path.write_text(
        f'recaptcha_site_key = "6Lc{BODY}{BODY[:13]}"\nstripe_key = "pk_live_{BODY}"\npassword = "sunshine"\n'
    )
    file = File(path=str(path), relative_path='settings.py')
    untagged_rules = [rule for rule in variable_rules if rule.tag is None]
    assert len(untagged_rules) == len(variable_rules) - 2

    def report(rules):
        from deepsecrets.core.tokenizers.lexer import LexerTokenizer
        from tests.case_helpers import run

        findings, _, _ = run(file, SemanticEngine(ruleset=rules), LexerTokenizer(deep_token_inspection=True))
        return [(f.start_offset, f.final_rule.id, f.final_rule.confidence) for f in findings]

    assert report(variable_rules) == report(untagged_rules)


def test_tags_survive_merging_and_pickling():
    file = File(path='/repo/a.py', relative_path='a.py', content='x = "secret"\n')
    first = Finding(file=file, detection='secret', start_offset=5, end_offset=11, rules=[Rule(id='S105')])
    second = Finding(file=file, detection='secret', start_offset=5, end_offset=11, rules=[Rule(id='S36')])
    first.tags, second.tags = [PUBLISHABLE], [TEST_CONTEXT, PUBLISHABLE]
    assert first.merge(second)
    assert first.tags == [PUBLISHABLE, TEST_CONTEXT]
    assert pickle.loads(pickle.dumps(first)).tags == [PUBLISHABLE, TEST_CONTEXT]
    # a finding of another span is not merged, and keeps its tags
    other = Finding(file=file, detection='x', start_offset=0, end_offset=1, rules=[Rule(id='S0')])
    assert not other.merge(first) and other.tags == []


@pytest.mark.parametrize(
    'path',
    [
        'tests/test_client.py',
        'test/app.js',
        'src/__tests__/client.ts',
        'pkg/client_test.go',
        'src/client.test.js',
        'src/client.spec.ts',
        'spec/models/user_spec.rb',
        'src/test/java/ClientTest.java',
        'Tests/Unit/ClientTests.cs',
        'UserSpec.scala',
        'app/fixtures/users.json',
        'fixtures.py',
        'src/__mocks__/api.js',
        'src/mocks/api.ts',
        'user.mock.ts',
        'examples/config.yml',
        'docs/example/app.py',
        'samples/demo.py',
        '.env.example',
        'config.example.yml',
        'settings.sample',
        'testdata/key.pem',
        'integration-tests/run.sh',
        'test_utils/helpers.py',
    ],
)
def test_test_context_paths(path):
    assert in_test_context(path)
    assert in_test_context(path.replace('/', '\\'))


@pytest.mark.parametrize(
    'path',
    [
        'src/settings.py',
        'src/latest/app.py',
        'contest/rules.py',
        'attestation/verify.go',
        'src/testimonials.js',
        'src/mocked.js',
        'src/sampler.py',
        'downsamples/x.py',
        'src/Contest.java',
        'rpm/package.spec',
        'lib/specification.md',
    ],
)
def test_not_test_context_paths(path):
    assert not in_test_context(path)


def test_test_context_reads_the_relative_path():
    # the absolute path holds /tests/: where the checkout sits does not matter (KI-ENG-25)
    in_tests = File(path='/home/ci/tests/repo/src/a.py', relative_path='src/a.py', content='x = 1\n')
    test_file = File(path='/srv/repo/tests/a.py', relative_path='tests/a.py', content='x = 1\n')
    findings = [
        Finding(file=in_tests, detection='1', start_offset=4, end_offset=5),
        Finding(file=test_file, detection='1', start_offset=4, end_offset=5),
        Finding(file=test_file, detection='x', start_offset=0, end_offset=1, tags=[PUBLISHABLE]),
    ]
    tag_test_context(findings)
    assert [f.tags for f in findings] == [[], [TEST_CONTEXT], [PUBLISHABLE, TEST_CONTEXT]]


@pytest.mark.parametrize(
    'path, recorded',
    [
        ('spec/fixtures/vcr_cassettes/login.yml', True),
        ('spec/cassettes/Projects/get.yml', True),
        ('tests/recordings/test_upload.json', True),
        ('sdk/tests/SessionRecords/Keys/List.json', True),
        ('capture.har', True),
        ('src/vcr.py', False),  # a module, not a directory of recordings
        ('lib/cassette.rb', False),
        ('fixtures/users.json', False),
    ],
)
def test_recorded_traffic_paths(path, recorded):
    assert in_recorded_traffic(path) is recorded


def _variable_finding(relative_path: str, *rules: Rule) -> Finding:
    file = File(path=f'/srv/repo/{relative_path}', relative_path=relative_path, content='token: "x"\n')
    finding = Finding(file=file, detection='x', start_offset=8, end_offset=9, rules=list(rules))
    finding.choose_final_rule()
    return finding


def test_recorded_traffic_lowers_s105_into_low_and_tags_it():
    s105 = Rule(id='S105', name='High Entropy and Variable Naming', confidence=8, is_dynamic_confidence=True)
    recorded = _variable_finding('spec/cassettes/login.yml', s105)
    elsewhere = _variable_finding('src/settings.py', s105)
    apply_path_context([recorded, elsewhere])
    assert (recorded.final_rule.id, recorded.final_rule.confidence) == ('S105', 4)
    assert recorded.tags == [TEST_CONTEXT, RECORDED_TRAFFIC]  # spec/ is a test path too
    assert (elsewhere.final_rule.confidence, elsewhere.tags) == (8, [])
    assert s105.confidence == 8  # the rule object other findings share is left alone


def test_a_typed_rule_in_recorded_traffic_keeps_its_confidence():
    s105 = Rule(id='S105', name='High Entropy and Variable Naming', confidence=9, is_dynamic_confidence=True)
    typed = Rule(id='S38', name='Google API Key', confidence=7)
    finding = _variable_finding('tests/recordings/maps.json', s105, typed)
    apply_path_context([finding])
    assert (finding.final_rule.id, finding.final_rule.confidence) == ('S38', 7)
    assert finding.tags == [TEST_CONTEXT, RECORDED_TRAFFIC]
