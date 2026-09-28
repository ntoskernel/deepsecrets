from deepsecrets.core.model.rules.regex_candidate_scoring import RegexCandidateScoringRule
from deepsecrets.core.rulesets.ibuilder import IRulesetBuilder


class RegexCandidateScoringRulesetBuilder(IRulesetBuilder):
    rule_model = RegexCandidateScoringRule
    ruleset_name = 'regex_candidate_scoring'
