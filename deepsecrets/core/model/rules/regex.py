import regex as re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, ForwardRef, List, Optional, Tuple, Union

from pydantic import ConfigDict, Field, field_serializer, model_validator

from deepsecrets.core.helpers.entropy import EntropyHelper
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.model.token import Token

RegexRule = ForwardRef('RegexRule')


class GroupType(str, Enum):
    """What a capture group of a regex rule holds, declared in its `match_rules` entry. A regex match typed this way is
    a candidate: like a variable, it has a value and sometimes a name, plus what the rule knows around them."""

    VALUE = 'value'  # the text the candidate rules judge; default: the reported text (target_group)
    NAME = 'name'  # what the value is assigned to, like a variable's name
    USER = 'user'  # the account a credential belongs to
    HOST = 'host'  # the service a credential opens
    KIND = 'kind'  # a sub-type the rule distinguishes (an AWS key id's prefix)


class Encoding(str, Enum):
    """How a value group's text is encoded, declared next to its type (`{"type": "value", "encoding": "base64"}`). The
    candidate then judges the payload (core/helpers/encoding.py): the share outside the alphabet, the randomness
    against it, the checksum."""

    BASE64 = 'base64'
    BASE32 = 'base32'
    HEX = 'hex'
    BASE58CHECK = 'base58check'  # carries a checksum


class Evidence(str, Enum):
    """What a regex rule's match proves, which decides the regex-candidate rules that apply to it."""

    FORMAT = 'format'  # the match proves the secret type: a key block, a prefixed or checksummed token
    SHAPE = 'shape'  # the match is only a shape (a URL password, an AWS key id) and needs corroboration


@dataclass
class RuleMatch:
    """One match of a rule: the reported span, and the match itself for its groups. A hit in decoded content reports
    the whole encoded token as its span, while `match` is the match in the decoded text."""

    start: int
    end: int
    match: re.Match


class RegexRule(Rule):  # type: ignore
    pattern: re.Pattern
    negative_pattern: Optional[re.Pattern] = Field(default=None)
    match_rules: Optional[Dict[int, RegexRule]] = Field(default={})  # type: ignore
    target_group: int = Field(default=0)
    entropy_settings: Optional[float] = Field(default=None)
    escaping_needed: bool = False
    case_sensitive: bool = False
    # which regex-candidate rules apply to this rule's matches (rules/regex_candidate_scoring_rules.json). None, the
    # default for a user's own rules, leaves its matches unjudged, as before 2.2
    evidence: Optional[Evidence] = Field(default=None)
    # on a match_rules entry: what its capture group holds (the text of the group must also match the entry)
    type: Optional[GroupType] = Field(default=None)
    # on a match_rules entry typed `value`: how the value is encoded
    encoding: Optional[Encoding] = Field(default=None)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @field_serializer('pattern')
    def serialize_dt(self, pattern: re.Pattern, _info):
        return pattern.pattern

    @model_validator(mode='before')
    @classmethod
    def build_pattern(cls, values: Dict) -> Dict:
        pattern_str = values.get('pattern', None)
        negative_pattern_str = values.get('negative_pattern', None)

        if pattern_str is not None and isinstance(pattern_str, str):
            escaping_needed = values.get('escaping_needed', False)

            flags = 0
            case_sensitive = values.get('case_sensitive', False)
            if escaping_needed:
                pattern_str = re.escape(pattern_str)

            if case_sensitive is False:
                flags = flags | re.IGNORECASE

            values['pattern'] = re.compile(pattern_str, flags)

        if negative_pattern_str is not None and isinstance(negative_pattern_str, str):
            escaping_needed = values.get('escaping_needed', False)

            flags = 0
            case_sensitive = values.get('case_sensitive', False)
            if escaping_needed:
                negative_pattern_str = re.escape(negative_pattern_str)

            if case_sensitive is False:
                flags = flags | re.IGNORECASE

            values['negative_pattern'] = re.compile(negative_pattern_str, flags)

        match_rules = values.get('match_rules', {})
        for _, match_rule in match_rules.items():
            match_rule['id'] = ''
            match_rule['confidence'] = 9
            # a group can be typed without being constrained
            match_rule.setdefault('pattern', '.*')

        return values

    @model_validator(mode='after')
    def one_group_per_type(self) -> 'RegexRule':
        types = [rule.type for rule in (self.match_rules or {}).values() if rule.type is not None]
        if len(types) != len(set(types)):
            raise ValueError(f'rule {self.id}: a group type is declared twice in match_rules')
        for rule in (self.match_rules or {}).values():
            if rule.encoding is not None and rule.type != GroupType.VALUE:
                raise ValueError(f'rule {self.id}: only the group typed value declares an encoding')
        return self

    def encoding_of_value(self) -> Optional[Encoding]:
        """The encoding the value group declares, if any."""
        index = self.group_of(GroupType.VALUE)
        return self.match_rules[index].encoding if index is not None else None  # type: ignore

    def group_of(self, type: GroupType) -> Optional[int]:
        """The capture group declared with this type, if any."""
        for group, rule in (self.match_rules or {}).items():
            if rule.type == type:
                return int(group)
        return None

    def __hash__(self) -> int:  # pragma: nocover
        return hash(self.id)

    def match(self, token: Union[Token, str]) -> List[Tuple[int, int]]:
        return [(m.start, m.end) for m in self.matches(token)]

    def matches(self, token: Union[Token, str]) -> List[RuleMatch]:
        good_matches = []
        contents = []
        contents.append(token.content if isinstance(token, Token) else token)
        contents.extend(token.uncovered_content if isinstance(token, Token) else [])

        # Call the compiled patterns directly: the module-level regex functions re-enter the pattern
        # cache on every call, which costs several times the match itself on short tokens.
        for i, content in enumerate(contents):
            if self.negative_pattern is not None and self.negative_pattern.search(content) is not None:
                continue

            for match in self.pattern.finditer(content):
                if not self._verify(match):
                    continue

                if i == 0:
                    start, end = match.span(self.target_group)
                    good_matches.append(RuleMatch(start, end, match))
                else:
                    good_matches.append(RuleMatch(0, len(contents[0]), match))

        return good_matches

    def _verify(self, match: re.Match) -> bool:
        match_ok = True
        entropy_ok = True

        if self.match_rules is not None:
            for group_i, match_rule in self.match_rules.items():
                span = match.span(group_i)
                window = match.string[span[0] : span[1]]
                if not match_rule.match(window):  # type: ignore
                    match_ok = False
                    return False

        if self.entropy_settings is not None:
            span = match.span(self.target_group)
            str_to_check = match.string[span[0] : span[1]]
            ent = EntropyHelper.get_for_string(str_to_check)
            if ent < self.entropy_settings:
                entropy_ok = False

        return match_ok and entropy_ok


RegexRule.model_rebuild()  # type: ignore


class RegexRuleWithoutId(RegexRule):
    id: Optional[str] = Field(default=None)
