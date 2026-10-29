"""Confidence tiers in SARIF, the INFO tier of rejected candidates, and --confidence-level."""

from types import SimpleNamespace

import pytest

from deepsecrets.cli import DeepSecretsCliTool
from deepsecrets.config import CONFIDENCE_LEVELS, TIER_FLOORS, Config
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.response.dojo_sarif import DojoSarifResponseBuilder
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.modes.iscan_mode import ScanMode


def meta(rule, rejected=False):
    return DojoSarifResponseBuilder()._sarif_rule_meta_from_rule(rule, rejected)


def test_the_tier_names_the_confidence_and_the_severity_stays_the_same():
    high = meta(Rule(id='S35', name='AWS Access Key ID', confidence=7, is_dynamic_confidence=True))
    low = meta(Rule(id='S35', name='AWS Access Key ID', confidence=1, is_dynamic_confidence=True))
    static = meta(Rule(id='S0', name='Slack Token', confidence=10))
    assert (high.id, low.id, static.id) == ('S35-HIGH', 'S35-LOW', 'S0')
    assert high.payload['properties']['precision'] == 'high' and low.payload['properties']['precision'] == 'low'
    severities = {m.payload['properties']['security-severity'] for m in (high, low, static)}
    assert severities == {DojoSarifResponseBuilder.SECURITY_SEVERITY}


def test_a_rejected_candidate_is_in_the_info_tier():
    info = meta(Rule(id='S19', name='Password in URL', confidence=0, is_dynamic_confidence=True), rejected=True)
    assert info.id == 'S19-INFO' and info.payload['properties']['precision'] == 'low'
    # a kept finding with confidence 0 stays LOW: INFO is for rejected candidates only
    assert meta(Rule(id='S106', confidence=0, is_dynamic_confidence=True)).id == 'S106-LOW'


def finding(rule_id, confidence, rejected=False, start=0):
    rule = Rule(id=rule_id, confidence=confidence, is_dynamic_confidence=True)
    return Finding(detection='x', start_offset=start, end_offset=start + 1, rules=[rule], rejected=rejected)


@pytest.mark.parametrize(
    'level, expected',
    [
        ('all', ['rejected', 'zero', 'low', 'four', 'medium', 'high', 'very-high']),
        ('low', ['zero', 'low', 'four', 'medium', 'high', 'very-high']),
        ('medium', ['medium', 'high', 'very-high']),
        ('high', ['high', 'very-high']),
        ('very-high', ['very-high']),
    ],
)
def test_the_confidence_level_filters_the_report(level, expected):
    # 2.3: MEDIUM starts at 5, so 4 is LOW
    findings = {
        'rejected': finding('S19', 0, rejected=True, start=0),
        'zero': finding('S106', 0, start=2),
        'low': finding('S105', 2, start=4),
        'four': finding('S105', 4, start=6),
        'medium': finding('S105', 5, start=8),
        'high': finding('S105', 6, start=10),
        'very-high': finding('S105', 9, start=12),
    }
    config = Config()
    config.set_confidence_level(level)
    kept = ScanMode.filter_by_confidence_level(SimpleNamespace(config=config), list(findings.values()))
    assert [name for name, f in findings.items() if f in kept] == expected


def test_the_tiers_are_low_0_to_4_medium_5_high_6_to_8_and_very_high_9_and_10():
    tiers = [meta(Rule(id='S105', confidence=c, is_dynamic_confidence=True)).id for c in range(11)]
    assert tiers == ['S105-LOW'] * 5 + ['S105-MEDIUM'] + ['S105-HIGH'] * 3 + ['S105-VERY-HIGH'] * 2


@pytest.mark.parametrize('confidence', range(11))
def test_the_sarif_tier_is_the_highest_level_whose_floor_the_confidence_reaches(confidence):
    # one table: the level filter and the rule-id suffix cannot disagree
    level = max((name for name, floor in TIER_FLOORS.items() if confidence >= floor), key=TIER_FLOORS.get)
    rule_meta = meta(Rule(id='S105', confidence=confidence, is_dynamic_confidence=True))
    assert rule_meta.id == f'S105-{level.upper()}'
    assert rule_meta.payload['properties']['precision'] == level
    # and that level is the highest whose filter keeps the finding
    kept_at = []
    for name in TIER_FLOORS:
        config = Config()
        config.set_confidence_level(name)
        if ScanMode.filter_by_confidence_level(SimpleNamespace(config=config), [finding('S105', confidence)]):
            kept_at.append(name)
    assert kept_at[-1] == level


def test_the_levels_are_the_tiers_and_all():
    assert CONFIDENCE_LEVELS == {'all': None, 'low': 0, 'medium': 5, 'high': 6, 'very-high': 9}


def test_an_unknown_level_is_refused():
    with pytest.raises(ValueError):
        Config().set_confidence_level('info')


def test_the_flag_sets_the_level():
    args = ['', '--target-dir', 'tests/fixtures', '--outfile', '/tmp/x.sarif', '--confidence-level', 'high']
    tool = DeepSecretsCliTool(args=args)
    tool.parse_arguments()
    assert tool.get_current_config().confidence_level == 'high'
    tool = DeepSecretsCliTool(args=args[:-2])
    tool.parse_arguments()
    assert tool.get_current_config().confidence_level == 'low'
