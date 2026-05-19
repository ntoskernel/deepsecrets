from typing import List

from deepsecrets.core.helpers.variable_evaluator import EvaluationResult, VariableEvaluator
from deepsecrets.core.utils.log import logger
from deepsecrets.core.engines.iengine import IEngine
from deepsecrets.core.helpers.content_analyzer import ContentAnalyzer
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

        if self.subengine is not None:  # pragma: nocover
            content_findings = ContentAnalyzer(self.subengine).analyze(token)
            if content_findings is not None:
                findings.extend(content_findings)

        if token.semantic is None:
            return findings

        if token.semantic.creds_probability == 9:
            findings.append(
                Finding(
                    detection=token.content,
                    start_offset=0,
                    end_offset=len(token.content),
                    rules=[Rule(id='S107', name='Dangerous condition', confidence=9)],
                )
            )

        if token.semantic.type == SemanticType.VARIABLE:
            try:

                if len(token.content) == 1:
                    return findings

                if len(token.content.split(' ')) > 1:
                    return findings

                evaluation_result: EvaluationResult = self.variable_evaluator.evaluate(token.semantic.payload)
                dangerous_variable = evaluation_result.is_dangerous

                if not dangerous_variable:
                    return findings

                if evaluation_result.entropy_score > 0:
                    findings.append(
                        Finding(
                            detection=token.content,
                            start_offset=0,
                            end_offset=len(token.content),
                            rules=[
                                Rule(
                                    id='S105',
                                    name='Entropy+Var naming',
                                    confidence=evaluation_result.export_confidence,
                                )
                            ],
                            internal_score={'var': token.semantic.name} | evaluation_result.summary(),
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            detection=token.content,
                            start_offset=0,
                            end_offset=len(token.content),
                            rules=[
                                Rule(
                                    id='S106',
                                    name='Var naming',
                                    confidence=evaluation_result.export_confidence,
                                )
                            ],
                            internal_score={'var': token.semantic.name} | evaluation_result.summary(),
                        )
                    )

            except Exception as e:
                logger.error(f'Problem during variable evaluation {e}')

        return findings
