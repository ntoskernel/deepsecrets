import regex as re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers.semantic.language import Language


class Match(BaseModel):
    types: List[Any] = Field(default_factory=list)
    values: List[re.Pattern] = Field(default_factory=list)
    not_values: List[re.Pattern] = Field(default_factory=list)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def check(self, tokens: List[Token]) -> bool:

        types_match = self._check_types(tokens)
        values_match = self._check_values(tokens)
        not_values_match = self._check_not_values(tokens)

        if not types_match:
            return False

        if not values_match:
            return False

        if not_values_match:
            return False

        return True

    def _check_types(self, tokens):
        if len(self.types) == 0:
            return True  # should match any type

        for token in tokens:
            if token.type[0] in self.types:
                return True
        return False

    def _check_values(self, tokens):
        if len(self.values) == 0:
            return True  # should match any value

        for token in tokens:
            for pattern in self.values:
                if pattern.match(token.content) is not None:
                    return True
        return False

    def _check_not_values(self, tokens):
        if len(self.not_values) == 0:
            return False

        for token in tokens:
            for pattern in self.not_values:
                if pattern.match(token.content) is not None:
                    return True
        return False

    @field_validator('values', 'not_values', mode='before')
    def regexify_values(cls, values: Dict) -> List[re.Pattern]:
        if values is None:
            return values

        if not isinstance(values, list):
            raise Exception('value must be an array')

        patterns = []
        for val in values:
            if isinstance(val, re.Pattern):
                patterns.append(val)
                continue

            patterns.append(re.compile(re.escape(val), re.IGNORECASE))

        return patterns


class RegionDetector(BaseModel):
    language: Optional[Language] = None
    languages_exclude: List[Language] = Field(default_factory=list)
    stream_pattern: re.Pattern
    overlapped: bool = Field(default=True)

    match_rules: Dict[int, Match]
    match_semantics: Dict[int | str, str]

    # Useful when positive lookaheads are used as a Match's span window is empty
    span_by_group_index: Optional[int] = None
    creds_probability: int = 0
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def match(self, tokens: List[Token], token_stream: str) -> List['Variable']:
        true_detections = []
        for match in re.finditer(self.stream_pattern, token_stream, overlapped=True):
            if not self._verify(match, tokens):
                continue

            reg = Region()
            for i, name in self.match_semantics.items():
                if isinstance(i, int):
                    setattr(reg, name, [match.span(i)[0], match.span(i)[1]])
                elif isinstance(i, str):
                    setattr(reg, name, i)
                else:
                    pass

            reg.found_by = self
            reg.span = [match.span(0)[0], match.span(0)[1]]

            true_detections.append(reg)

        return true_detections

    def _verify(self, match: re.Match, tokens: List[Token]) -> bool:
        for group_i, match_rule in self.match_rules.items():
            span = match.span(group_i)
            window = tokens[span[0] : span[1]]

            if not match_rule.check(window):
                return False

        return True


class VariableDetector(RegionDetector):
    creds_probability: int = 0

    def match(self, tokens: List[Token], token_stream: str) -> List['Variable']:
        true_detections = []

        for match in re.finditer(self.stream_pattern, token_stream, overlapped=True):
            if not self._verify(match, tokens):
                continue

            var = Variable()
            for i, name in self.match_semantics.items():
                if isinstance(i, int):
                    setattr(var, name, tokens[match.span(i)[0]])
                elif isinstance(i, str):
                    setattr(var, name, i)
                else:
                    pass

            var.found_by = self

            if self.span_by_group_index is not None:
                span_group = match.span(self.span_by_group_index)
                var.span = [span_group[0], span_group[1]]
            else:
                var.span = [match.span(0)[0], match.span(0)[1]]

            true_detections.append(var)

        return true_detections


class VariableSuppressor(VariableDetector):

    def match(self, tokens: List[Token], token_stream: str) -> List['Variable']:
        detections = super().match(tokens, token_stream)
        spans = []
        for detection in detections:
            spans.append(detection.span)

        return spans


class CheapVariableDetector(RegionDetector):

    def match(self, content: str) -> List['Variable']:
        true_detections = []
        for m in re.finditer(self.stream_pattern, content, overlapped=self.overlapped):
            if not self._verify(m):
                continue

            var = Variable()
            for i, name in self.match_semantics.items():
                if isinstance(i, int):
                    setattr(var, name, content[m.span(i)[0] : m.span(i)[1]])
                elif isinstance(i, str):
                    setattr(var, name, i)
                else:
                    pass

            var.found_by = self

            if self.span_by_group_index is not None:
                span_group = m.span(self.span_by_group_index)
                var.span = [span_group[0], span_group[1]]
            else:
                var.span = [m.span(0)[0], m.span(0)[1]]

            true_detections.append(var)

        return true_detections

    def _verify(self, match: re.Match) -> bool:
        match_ok = True

        if self.match_rules is not None:
            for group_i, match_rule in self.match_rules.items():
                span = match.span(group_i)
                window = match.string[span[0] : span[1]]
                if not match_rule.match(window):  # type: ignore
                    match_ok = False
                    return False

        return match_ok


from deepsecrets.core.model.semantic import Region, Variable
