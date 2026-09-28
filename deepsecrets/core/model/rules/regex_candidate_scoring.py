import operator
from enum import Enum
from typing import Any, Dict, List, Optional

import regex as re
from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator

from deepsecrets.core.model.rules.rule import Rule


class CandidateTarget(str, Enum):
    """A field of RegexCandidateContext. The name is the field's, upper-cased."""

    NAME_SPACED = 'NAME_SPACED'
    NAME_NORMALIZED = 'NAME_NORMALIZED'
    VALUE = 'VALUE'
    VALUE_NORMALIZED = 'VALUE_NORMALIZED'
    VALUE_LENGTH = 'VALUE_LENGTH'
    VALUE_NORMALIZED_NATURALNESS_SCORE = 'VALUE_NORMALIZED_NATURALNESS_SCORE'
    VALUE_ENTROPY = 'VALUE_ENTROPY'  # Shannon entropy, bits per character
    VALUE_RANDOMNESS = 'VALUE_RANDOMNESS'  # entropy over a random string's of the same length and alphabet: ~1 random
    VALUE_FOREIGN_SHARE = 'VALUE_FOREIGN_SHARE'  # share of the value outside its declared encoding's alphabet
    VALUE_CHECKSUM = 'VALUE_CHECKSUM'  # valid, invalid, or none (no checksummed encoding declared)
    FILEPATH = 'FILEPATH'
    USER = 'USER'
    HOST = 'HOST'
    HOST_KIND = 'HOST_KIND'  # public, local, placeholder or none
    KIND = 'KIND'
    RULE = 'RULE'  # the regex rule's id
    EVIDENCE = 'EVIDENCE'  # the regex rule's evidence label: format or shape


OPS = {
    '<=': operator.le,
    '>=': operator.ge,
    '==': operator.eq,
    '!=': operator.ne,
    '<': operator.lt,
    '>': operator.gt,
}


# the fields a comparison (`method` with `threshold`) can test; the others are text
NUMERIC_TARGETS = frozenset(
    {
        CandidateTarget.VALUE_LENGTH,
        CandidateTarget.VALUE_NORMALIZED_NATURALNESS_SCORE,
        CandidateTarget.VALUE_ENTROPY,
        CandidateTarget.VALUE_RANDOMNESS,
        CandidateTarget.VALUE_FOREIGN_SHARE,
    }
)


class CandidateTest(BaseModel):
    """A test of one field, in exactly one form: `pattern` (a case-insensitive regex search on its text), `method`
    with `threshold` (a numeric comparison), `equals` (its text is this value) or `in` (its text is one of these)."""

    target: CandidateTarget
    pattern: Optional[re.Pattern] = None
    method: Optional[str] = None
    threshold: Optional[float] = None
    equals: Optional[str] = None
    in_: Optional[List[str]] = Field(default=None, alias='in')

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)

    @model_validator(mode='before')
    @classmethod
    def compile_pattern(cls, values: Dict) -> Dict:
        pattern = values.get('pattern')
        if isinstance(pattern, str):
            values['pattern'] = re.compile(pattern, re.IGNORECASE)
        return values

    @model_validator(mode='after')
    def one_form(self) -> 'CandidateTest':
        forms = [
            self.pattern is not None,
            self.method is not None or self.threshold is not None,
            self.equals is not None,
            self.in_ is not None,
        ]
        if sum(forms) != 1:
            raise ValueError(f'{self.target.value}: give one of pattern, method and threshold, equals, or in')
        if forms[1] and (self.method not in OPS or self.threshold is None):
            raise ValueError(f'{self.target.value}: a comparison needs a method ({", ".join(OPS)}) and a threshold')
        if forms[1] and self.target not in NUMERIC_TARGETS:
            # caught here, when the rules load: at scan time the comparison would raise and abandon the file
            raise ValueError(f'{self.target.value}: a comparison needs a numeric field, and this one is text')
        return self

    @field_serializer('pattern')
    def serialize_pattern(self, pattern: Optional[re.Pattern], _info):
        return pattern.pattern if pattern is not None else None

    def holds(self, context: Any) -> bool:
        content = getattr(context, self.target.value.lower())
        if self.pattern is not None:
            return self.pattern.search(str(content)) is not None
        if self.equals is not None:
            return str(content) == self.equals
        if self.in_ is not None:
            return str(content) in self.in_
        return OPS[self.method](content, self.threshold)


class CandidateCondition(CandidateTest):
    """A `when` condition, or one of a case's `if` conditions."""


class CandidateCase(BaseModel):
    """A sub-condition of a rule with its own score: applies when every `if` condition holds."""

    name: Optional[str] = None
    conditions: List[CandidateCondition] = Field(alias='if')
    score: int

    model_config = ConfigDict(populate_by_name=True)

    def holds(self, context: Any) -> bool:
        return all(condition.holds(context) for condition in self.conditions)


class RegexCandidateScoringRule(Rule, CandidateTest):
    """A rule judging regex candidates (a separate ruleset from the variable-scoring rules).

    It fires when every `when` condition holds and its own test does. A fired rule adds its `score`, then the score of
    the first of its `cases` that holds, if any. Rules add up; RegexCandidateEvaluator rejects a candidate whose total
    reaches REJECT_AT and turns a kept `shape` candidate's total into its confidence. Scores are confidence points.
    """

    when: List[CandidateCondition] = Field(default=[])
    score: int = 0
    cases: List[CandidateCase] = Field(default=[])

    def fires(self, context: Any) -> bool:
        return all(condition.holds(context) for condition in self.when) and self.holds(context)

    def case_for(self, context: Any) -> Optional[CandidateCase]:
        """For a rule that fired: the first case that holds."""
        return next((case for case in self.cases if case.holds(context)), None)
