from typing import List, Optional

from deepsecrets.core.engines.iengine import IEngine
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.rules.regex import RegexRule, RuleMatch
from deepsecrets.core.model.token import Token


class RegexEngine(IEngine):
    name = 'regex'
    description = 'Scans by regex patterns provided by RegexRules'

    def __init__(
        self, ruleset: Optional[List] = None, candidate_rules: Optional[List] = None, report_rejected: bool = False
    ) -> None:
        super().__init__(ruleset=ruleset if ruleset is not None else [])
        # a regex match is a candidate, judged here as it is found, as the semantic engine judges a variable
        self.evaluator = None
        if candidate_rules:
            # imported here: the evaluator reads the naturalness model, which a regex-only engine does not need
            from deepsecrets.core.helpers.regex_candidate_evaluator import RegexCandidateEvaluator
            from deepsecrets.core.model.regex_candidate import RegexCandidateContext

            self.evaluator = RegexCandidateEvaluator(candidate_rules)
            self.candidate_context = RegexCandidateContext
        # rejected candidates are reported (confidence 0, flagged) only at --confidence-level all
        self.report_rejected = report_rejected
        # the diagnostics tracer sets a list here to record every rejection, in file offsets, without emitting them
        self.rejected_log: Optional[list] = None

    def search(self, token: Token, corroborated: bool = False) -> List[Finding]:
        """`corroborated`: the semantic engine reported this token's variable, so a match covering the whole token is
        already judged and keeps its rule's confidence."""
        results = []

        for rule in self.ruleset:
            if not self.is_rule_applicable(token=token, rule=rule):
                continue

            results.extend(self._check_rule(token, rule, corroborated))  # type: ignore
        return results

    def _check_rule(self, token: Token, rule: RegexRule, corroborated: bool = False) -> List[Finding]:
        findings: List[Finding] = []

        for match in rule.matches(token):
            if match.start == match.end:
                continue  # an empty group (password= with nothing after it): nothing to report
            finding = Finding(
                rules=[rule],
                detection=token.content[match.start : match.end],
                start_offset=match.start,
                end_offset=match.end,
            )
            if self._judge(finding, token, rule, match, corroborated):
                findings.append(finding)

        return findings

    def _judge(self, finding: Finding, token: Token, rule: RegexRule, match: RuleMatch, corroborated: bool) -> bool:
        """Whether to emit the finding; sets its confidence, or marks it rejected."""
        if self.evaluator is None or rule.evidence is None:
            return True
        if corroborated and (match.start, match.end) == (0, len(token.content)):
            return True

        context = self.candidate_context.from_match(rule, match.match, finding.detection, token.file.path)
        verdict = self.evaluator.evaluate(context)
        if verdict.rejected:
            if self.rejected_log is not None:
                offset = token.span[0] if token.span else 0
                self.rejected_log.append(
                    {
                        'span': (offset + match.start, offset + match.end),
                        'rule': rule.id,
                        'evidence': rule.evidence.value,
                    }
                    | verdict.summary()
                )
            if not self.report_rejected:
                return False
            finding.rejected = True
            finding.rules = [rule.model_copy(update={'confidence': 0, 'is_dynamic_confidence': True})]
            finding.internal_score = {'candidate': verdict.summary()}
            return True
        if verdict.confidence is not None:
            finding.rules = [rule.model_copy(update={'confidence': verdict.confidence, 'is_dynamic_confidence': True})]
        return True
