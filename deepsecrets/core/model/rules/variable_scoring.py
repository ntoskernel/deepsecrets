from enum import Enum
import operator
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator
from deepsecrets.core.model.rules.regex import RegexRule
from deepsecrets.core.model.semantic import Context
import regex as re


class Target(str, Enum):
    NAME_SPACED = "NAME_SPACED"  # "api access key"
    NAME_NORMALIZED = "NAME_NORMALIZED"  # "apiaccesskey" (Best for fuzzy)
    VALUE = "VALUE"
    FILEPATH = "FILEPATH"  # The file path
    VALUE_NORMALIZED = 'VALUE_NORMALIZED'
    VALUE_LENGTH = 'VALUE_LENGTH'
    VALUE_NORMALIZED_NATURALNESS_SCORE = 'VALUE_NORMALIZED_NATURALNESS_SCORE'


target_to_fields = {
    Target.FILEPATH: 'filepath',
    Target.NAME_SPACED: 'name_spaced',
    Target.VALUE: 'value',
    Target.NAME_NORMALIZED: 'name_normalized',
    Target.VALUE_NORMALIZED: 'value_normalized',
    Target.VALUE_LENGTH: 'value_length',
    Target.VALUE_NORMALIZED_NATURALNESS_SCORE: 'value_normalized_naturalness_score',
}

ops = {
    "<=": operator.le,
    ">=": operator.ge,
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    ">": operator.gt,
}


class ScoringCondition(BaseModel):
    """A case-insensitive regex check against one context field, used by `when` / `unless`."""

    target: Target
    pattern: re.Pattern

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @field_validator('pattern', mode='before')
    @classmethod
    def compile_pattern(cls, pattern):
        return re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern

    @field_serializer('pattern')
    def serialize_pattern(self, pattern: re.Pattern, _info):
        return pattern.pattern

    def matches(self, context: Context) -> bool:
        return self.pattern.search(str(getattr(context, target_to_fields[self.target]))) is not None


class VariableScoringRule(RegexRule):
    score: int
    target: Target
    method: Optional[str] = None
    threshold: Optional[float] = None
    # the rule can only fire when every `when` condition matches and no `unless` condition does
    when: List[ScoringCondition] = Field(default=[])
    unless: List[ScoringCondition] = Field(default=[])

    def _is_threshold_type(self):
        return self.threshold is not None and self.method is not None

    @model_validator(mode='before')
    @classmethod
    def build_numeric(cls, values: Dict) -> Dict:
        if 'method' not in values.keys() and 'threshold' not in values.keys():
            return values

        return values

    def _get_content_for_matching(self, context: Context):
        field = target_to_fields.get(self.target)
        return getattr(context, field)

    def match_by_context(self, context: Context) -> bool:
        if not all(condition.matches(context) for condition in self.when):
            return False
        if any(condition.matches(context) for condition in self.unless):
            return False

        content = self._get_content_for_matching(context)
        if self._is_threshold_type():
            match = ops.get(self.method)(content, self.threshold)
        else:
            match = self.pattern.search(content)
        if match is not None and match is not False:
            return True
        return False
