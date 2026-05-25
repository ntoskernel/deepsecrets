from dataclasses import dataclass, field
from typing import List, Union
from deepsecrets.core.helpers.entropy import EntropyHelper
from deepsecrets.core.model.rules.variable_scoring import VariableScoringRule
from deepsecrets.core.model.semantic import Context, Variable
from nostril import nonsense

# func = generate_nonsense_detector(min_score=8.1)


@dataclass
class EvaluationResult:
    is_dangerous: bool
    matched_rules: List[str] = field(default_factory=list)
    entropy: float = 0.0

    naming_and_content_score: float = 0.0
    entropy_score: float = 0.0
    nonsence_value_score: float = 0.0

    total_score: float = 0.0

    export_confidence: int = 0

    # < 3: 0
    # 3-4: 0 -> 35

    def summary(self) -> dict:
        return {
            'conf': self.export_confidence,
            'n+c': self.naming_and_content_score,
            'e': round(self.entropy_score, 2),
            'gib': self.nonsence_value_score,
        }


HOPELESS_THRESHOLD = -100
DANGER_THRESHOLD = 0


class VariableEvaluator:

    rules: List[VariableScoringRule]

    def __init__(self, rules: List[VariableScoringRule]) -> None:
        self.rules = rules

    def calculate_entropy_score(self, entropy: float) -> float:
        if entropy == 0:
            return -1

        if entropy < 3:
            return 0

        if 3 <= entropy < 4:
            return (entropy - 3) * 35

        return 40

    def _is_nonsense(self, token: str) -> float:
        if len(token) <= 6:
            return 0

        is_nonsense = True
        try:
            is_nonsense = nonsense(token)
        except ValueError:
            pass

        return 1 if is_nonsense is True else 0

    def calculate_nonsense_value_score(self, parts: List[str], normalized: str) -> float:
        if len(normalized) > 300:
            return 1  # obviously

        len_checks = 0
        applicable_parts = [t for t in parts if len(t) > 6]
        scores = 0

        for part in applicable_parts:
            try:
                scores += self._is_nonsense(part)
                len_checks += 1
            except Exception:
                pass

        normalized_string_score = 0
        if len(normalized) > 6:
            normalized_string_score = self._is_nonsense(normalized)

        if len_checks == 0:
            return 0
        return ((scores / len_checks) + normalized_string_score) / 2

    def evaluate(self, variable: Union[Variable | Context]) -> EvaluationResult:
        context = variable.context if isinstance(variable, Variable) else variable

        naming_and_content_score = 0
        matched_rules = []

        for rule in self.rules:
            fired = rule.match_by_context(context)
            if fired:
                naming_and_content_score += rule.score
                matched_rules.append(rule.id)

            if naming_and_content_score <= HOPELESS_THRESHOLD:
                return EvaluationResult(
                    total_score=naming_and_content_score,
                    is_dangerous=False,
                    matched_rules=matched_rules,
                )

        entropy = EntropyHelper.get_for_string(context.value)
        entropy_score = self.calculate_entropy_score(entropy)
        if entropy == 0 and entropy_score == -1:
            return EvaluationResult(
                total_score=naming_and_content_score,
                is_dangerous=False,
                entropy=entropy,
                entropy_score=entropy_score,
                matched_rules=matched_rules,
            )

        nonsense_value_score = (
            1 - context.value_normalized_naturalness_score
        )  # self.calculate_nonsense_value_score(context.value_parts, context.value_normalized)
        total_score = naming_and_content_score + entropy_score

        result = EvaluationResult(
            naming_and_content_score=naming_and_content_score,
            entropy=entropy,
            entropy_score=entropy_score,
            total_score=total_score,
            matched_rules=matched_rules,
            nonsence_value_score=nonsense_value_score,
            is_dangerous=naming_and_content_score > DANGER_THRESHOLD,
        )

        result.export_confidence = self.confidence_from_evaluation_result(result)
        return result

    def confidence_from_evaluation_result(self, result: EvaluationResult):
        entropy_part = 0
        var_part = result.naming_and_content_score / 25 * 10

        if result.entropy_score > 0:
            if result.naming_and_content_score <= 20:
                # var_naming: 0 -> 5
                # entropy: 0 -> 5
                var_part = result.naming_and_content_score / 25 * 5
                entropy_part = result.entropy_score / 40 * 5
            else:
                var_part = 5
                entropy_part = result.entropy_score / 40 * 5

            entropy_part = entropy_part * min(result.nonsence_value_score + 0.5, 1)
            # ep non

        if entropy_part > 5:
            entropy_part = 5

        if entropy_part < 0:
            entropy_part = 0

        if var_part > 10:
            var_part = 10

        if var_part < 0:
            var_part = 0

        return round(var_part + entropy_part)
