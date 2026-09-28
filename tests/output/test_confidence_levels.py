"""Confidence tiers in SARIF, the INFO tier of rejected candidates, and --confidence-level."""

from types import SimpleNamespace

import pytest

from deepsecrets.cli import DeepSecretsCliTool
from deepsecrets.config import Config
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
        ('all', ['rejected', 'zero', 'low', 'medium', 'high', 'very-high']),
        ('low', ['zero', 'low', 'medium', 'high', 'very-high']),
        ('medium', ['medium', 'high', 'very-high']),
        ('high', ['high', 'very-high']),
        ('very-high', ['very-high']),
    ],
)
def test_the_confidence_level_filters_the_report(level, expected):
    findings = {
        'rejected': finding('S19', 0, rejected=True, start=0),
        'zero': finding('S106', 0, start=2),
        'low': finding('S105', 2, start=4),
        'medium': finding('S105', 3, start=6),
        'high': finding('S105', 6, start=8),
        'very-high': finding('S105', 9, start=10),
    }
    config = Config()
    config.set_confidence_level(level)
    kept = ScanMode.filter_by_confidence_level(SimpleNamespace(config=config), list(findings.values()))
    assert [name for name, f in findings.items() if f in kept] == expected


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
