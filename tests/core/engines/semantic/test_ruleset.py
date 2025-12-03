from deepsecrets.core.rulesets.variable_scoring import VariableScoringRulesetBuilder
from deepsecrets.core.utils.fs import get_path_inside_package


def test_builder():
    builder = VariableScoringRulesetBuilder()
    builder.with_rules_from_file(get_path_inside_package('rules/variable_scoring_rules.json'))
    assert len(builder.rules) != 0
