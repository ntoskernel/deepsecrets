import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.model.token import Token

TEST_TOKEN_CONTENTS = '"amqp://fake_user:TESTSECRET1234@rabbitmq-esp01.miami.example.com:5672/esp"'
TOKEN_SPAN = (76, 151)

FINDING_CONTENT = 'TESTSECRET1234'
FINDING_SPAN_INSIDE_TOKEN = (18, 32)


@pytest.fixture(scope='module')
def rule() -> Rule:
    return Rule(id='test')


@pytest.mark.fixture_file_path('4.go')
def token(file: File) -> Token:
    return Token(
        file=file,
        content=TEST_TOKEN_CONTENTS,
        span=file.get_span_for_string(TEST_TOKEN_CONTENTS),
    )


@pytest.mark.fixture_file_path('4.go')
def test_1_finding(file: File, rule: Rule):
    _token = token(file)
    assert file.content[_token.span[0] : _token.span[1]] == TEST_TOKEN_CONTENTS

    new_finding = Finding(
        file=file,
        rules=[rule],
        start_offset=FINDING_SPAN_INSIDE_TOKEN[0],
        end_offset=FINDING_SPAN_INSIDE_TOKEN[1],
        detection=_token.content[FINDING_SPAN_INSIDE_TOKEN[0] : FINDING_SPAN_INSIDE_TOKEN[1]],
    )

    assert new_finding.detection == FINDING_CONTENT
    new_finding.map_on_file(relative_start=_token.span[0])

    assert new_finding.start_offset == TOKEN_SPAN[0] + FINDING_SPAN_INSIDE_TOKEN[0]
    assert new_finding.end_offset == TOKEN_SPAN[0] + FINDING_SPAN_INSIDE_TOKEN[1]


def test_final_rule_tie_goes_to_the_earlier_rule_whatever_the_order():
    # merged rules come out of a set, so their order depends on the hash seed (KI-DM-15)
    typed = Rule(id='S18', confidence=10, rank=18)
    generic = Rule(id='S26', confidence=10, rank=24)
    semantic = Rule(id='S105', confidence=10)  # made in code: default rank, loses ties to ruleset rules
    weaker = Rule(id='S0', confidence=9, rank=0)
    for rules in ([typed, generic, semantic, weaker], [semantic, weaker, generic, typed], [generic, typed]):
        finding = Finding(detection='x', start_offset=0, end_offset=1, rules=list(rules))
        finding.choose_final_rule()
        assert finding.final_rule.id == 'S18'


def test_ruleset_builder_ranks_rules_in_file_order():
    from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
    from deepsecrets.core.utils.fs import get_path_inside_package

    rules = RegexRulesetBuilder().with_rules_from_file(get_path_inside_package('rules/regexes.json')).rules
    assert [r.rank for r in rules] == list(range(len(rules)))
