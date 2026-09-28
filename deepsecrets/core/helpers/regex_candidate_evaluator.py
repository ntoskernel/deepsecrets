from dataclasses import dataclass, field
from typing import Dict, List, Optional

from deepsecrets.core.helpers.confidence import entropy_score, randomness_points
from deepsecrets.core.model.regex_candidate import RegexCandidateContext
from deepsecrets.core.model.rules.regex import Evidence
from deepsecrets.core.model.rules.regex_candidate_scoring import RegexCandidateScoringRule

# The confidence a `shape` match earns from itself, before its value is looked at: what a strong name gives a variable
# (S105's 0.2 points per naming point, up to 20). Rule scores are confidence points taken from it or given back.
CORROBORATION = 4
# A candidate is rejected when its total reaches this: one warning sign (-8) its cases did not buy back. A rule meant
# only to lower a kept candidate's confidence must stay small: a warning bought back leaves a total of -4, 4 points
# from here.
REJECT_AT = -8


@dataclass
class CandidateVerdict:
    rejected: bool
    # for a kept `shape` candidate; None keeps the regex rule's own confidence (a `format` match proves its type)
    confidence: Optional[int]
    total: int = 0
    # each fired rule, with the name of the case that applied (None when no case did)
    fired: Dict[str, Optional[str]] = field(default_factory=dict)
    # for a rejected candidate: the fired rule that took the most points
    reason: Optional[str] = None

    def summary(self) -> dict:
        return {
            'rejected': self.rejected,
            'confidence': self.confidence,
            'total': self.total,
            'fired': self.fired,
            'reason': self.reason,
        }


class RegexCandidateEvaluator:
    """Judges regex candidates with the regex-candidate scoring rules, as VariableEvaluator judges variables with the
    variable-scoring rules: every fired rule adds its score and its first matching case's. See
    docs/private/research/regex-candidates.md."""

    rules: List[RegexCandidateScoringRule]

    def __init__(self, rules: List[RegexCandidateScoringRule]) -> None:
        self.rules = rules

    def evaluate(self, context: RegexCandidateContext) -> CandidateVerdict:
        total = 0
        fired: Dict[str, Optional[str]] = {}
        contributions: List[tuple] = []
        for rule in self.rules:
            if not rule.fires(context):
                continue
            case = rule.case_for(context)
            points = rule.score + (case.score if case is not None else 0)
            total += points
            fired[rule.id] = case.name if case is not None else None
            contributions.append((points, rule.id))

        if total <= REJECT_AT:
            reason = min(contributions)[1] if contributions else None
            return CandidateVerdict(rejected=True, confidence=0, total=total, fired=fired, reason=reason)
        if context.evidence != Evidence.SHAPE.value:
            return CandidateVerdict(rejected=False, confidence=None, total=total, fired=fired)
        corroboration = min(max(CORROBORATION + total, 0), CORROBORATION)
        randomness = randomness_points(
            entropy_score(context.value_entropy), 1 - context.value_normalized_naturalness_score
        )
        confidence = round(min(corroboration + randomness, 10))
        return CandidateVerdict(rejected=False, confidence=confidence, total=total, fired=fired)
