from deepsecrets.core.model.rules.variable_scoring import VariableScoringRule
from deepsecrets.core.rulesets.ibuilder import IRulesetBuilder


class VariableScoringRulesetBuilder(IRulesetBuilder):
    rule_model = VariableScoringRule
    ruleset_name = 'variable_scoring'
