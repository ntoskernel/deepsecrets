from typing import List, Optional

from deepsecrets.config import WEAK_VALUE_MAX_CONFIDENCE
from deepsecrets.core.helpers.variable_evaluator import EvaluationResult, VariableEvaluator
from deepsecrets.core.utils.log import logger
from deepsecrets.core.engines.iengine import IEngine
from deepsecrets.core.helpers.content_analyzer import ContentAnalyzer
from deepsecrets.core.helpers.finding_tags import WEAK_PASSWORD
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.model.token import SemanticType, Token

filenames_ignorelist = [
    'package-lock.json',
    'package.json',
]

false_starting_sequences = [
    '${',
    'true',
    '%env',
]


class SemanticEngine(IEngine):
    name = 'semantic'
    subengine: IEngine = None
    variable_evaluator: VariableEvaluator

    def __init__(self, subengine: IEngine = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.subengine = subengine
        self.variable_evaluator = VariableEvaluator(self.ruleset)

    # token is a STRING with potential 'semantic' extension
    def search(self, token: Token) -> List[Finding]:
        findings: List[Finding] = []

        if token.length == token.file.length:
            return findings

        for fname in filenames_ignorelist:
            if fname in token.file.path:
                return findings

        # the variable first: a regex match that covers the whole token of a variable reported here is corroborated,
        # so the regex sub-engine does not judge it again
        semantic_findings = self._evaluate_semantics(token)

        if self.subengine is not None:  # pragma: nocover
            content_findings = ContentAnalyzer(self.subengine).analyze(token, corroborated=bool(semantic_findings))
            if content_findings is not None:
                findings.extend(content_findings)

        findings.extend(semantic_findings)
        return findings

    def _evaluate_semantics(self, token: Token) -> List[Finding]:
        """S107 for a dangerous condition; S105 or S106 for a variable the evaluator scores as dangerous. A variable
        whose evaluation raises is logged and skipped, not the file (KI-ENG-03)."""
        semantic = token.semantic
        if semantic is None:
            return []

        findings = []
        if semantic.creds_probability == 9:
            findings.append(whole_token_finding(token, Rule(id='S107', name='Dangerous condition', confidence=10)))

        # a single character, or several words: not a value a secret is assigned as
        if semantic.type != SemanticType.VARIABLE or len(token.content) == 1 or ' ' in token.content:
            return findings

        try:
            result = self.variable_evaluator.evaluate(semantic.payload)
            rule = variable_rule(result)
            if rule is not None:
                # the tags of the rules that fired; an S106 finding is a weak password too
                tags = [*result.tags, WEAK_PASSWORD] if rule.id == 'S106' else result.tags
                findings.append(whole_token_finding(token, rule, {'var': semantic.name} | result.summary(), tags))
        except Exception as e:
            logger.error(f'Problem during variable evaluation {e}')
        return findings


def variable_rule(result: EvaluationResult) -> Optional[Rule]:
    """The rule a variable is reported under, or None. S105 when its value earns an entropy score. S106 when it earns
    none (3 bits or less) but a rule allowed a low-entropy value: a password someone chose, else a placeholder, an id
    or a map key. S106 has no value evidence, so its confidence is capped in the LOW tier."""
    if not result.is_dangerous:
        return None
    if result.entropy_score > 0:
        return Rule(
            id='S105',
            name='High Entropy and Variable Naming',
            confidence=result.export_confidence,
            is_dynamic_confidence=True,
        )
    if result.allows_low_entropy:
        return Rule(
            id='S106',
            name='Variable Naming',
            confidence=min(result.export_confidence, WEAK_VALUE_MAX_CONFIDENCE),
            is_dynamic_confidence=True,
        )
    return None


def whole_token_finding(
    token: Token, rule: Rule, internal_score: Optional[dict] = None, tags: Optional[List[str]] = None
) -> Finding:
    return Finding(
        detection=token.content,
        start_offset=0,
        end_offset=len(token.content),
        rules=[rule],
        internal_score=internal_score if internal_score is not None else {},
        tags=list(dict.fromkeys(tags or [])),
    )
