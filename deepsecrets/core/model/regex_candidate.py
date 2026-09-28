from dataclasses import dataclass, field
from typing import Optional

import regex as re

from deepsecrets.core.helpers import encoding as encoded
from deepsecrets.core.helpers.entropy import EntropyHelper
from deepsecrets.core.model.rules.regex import GroupType, RegexRule
from deepsecrets.core.model.semantic import Context

HOST_END = re.compile(r'[/:?#\s"\'),;\]\\]')
LOCAL_HOST = re.compile(
    r'^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|host\.docker\.internal|[^.]+$)', re.I
)
PLACEHOLDER_HOST = re.compile(
    r'(^|\.)(example|foo|bar|baz|foobar|test|domain|yourdomain|mydomain|host|hostname|server|myserver|yourserver|'
    r'invalid|local|localdomain|tld|xxx|company|acme)(\.[a-z]+)?$|[<>{}$%*]|^(example|foo|bar)\.',
    re.I,
)


def host_kind(address: Optional[str]) -> str:
    """'public', 'local', 'placeholder' or 'none' for the text a host group holds (after a URL's '@', after a
    connection string's scheme): a dotted public name, localhost or a single-label service name, or a documentation
    domain such as example.com or foobar.com."""
    host = HOST_END.split(address or '', maxsplit=1)[0]
    if not host:
        return 'none'
    if PLACEHOLDER_HOST.search(host):
        return 'placeholder'
    if LOCAL_HOST.search(host):
        return 'local'
    return 'public'


@dataclass
class RegexCandidateContext(Context):
    """A regex match seen as a candidate, like a variable: a value, sometimes a name, and what the rule's typed groups
    hold around them. Name and value are normalised exactly as a variable's (Context); the regex-candidate scoring
    rules read these fields by target (rules/regex_candidate_scoring_rules.json)."""

    rule: str = ''
    evidence: str = ''
    user: str = ''
    host: str = ''
    kind: str = ''
    # the encoding the value group declares; with one, the value is its payload (core/helpers/encoding.py)
    encoding: str = ''
    host_kind: str = field(default='none', repr=False)
    value_entropy: float = field(default=0.0, repr=False)
    # the share of the value outside its encoding's alphabet (0 without an encoding)
    value_foreign_share: float = field(default=0.0, repr=False)
    # the value's entropy over a random string's of the same length and alphabet: about 1 when random
    value_randomness: float = field(default=0.0, repr=False)
    # 'valid' or 'invalid' for an encoding with a checksum, else 'none'
    value_checksum: str = field(default='none', repr=False)

    def __post_init__(self):
        if self.encoding:
            self.value = encoded.payload(self.value)
        super().__post_init__()
        self.host_kind = host_kind(self.host)
        self.value_entropy = EntropyHelper.get_for_string(self.value)
        self.value_foreign_share = encoded.foreign_share(self.value, self.encoding)
        self.value_randomness = encoded.randomness(self.value, self.value_entropy, self.encoding)
        self.value_checksum = encoded.checksum(self.value, self.encoding)

    @classmethod
    def from_match(
        cls, rule: RegexRule, match: Optional[re.Match], reported: str, filepath: str
    ) -> 'RegexCandidateContext':
        """The candidate a rule's match makes. The value is the group typed `value`, else the rule's target group, else
        the reported text; for a hit in decoded content the groups are the decoded text's. A value group that declares
        an encoding gives its payload as the value: a key body without its line breaks, quotes and headers."""

        def group(type: GroupType) -> str:
            index = rule.group_of(type)
            if index is None or match is None:
                return ''
            return match.group(index) or ''

        value_group = group(GroupType.VALUE)
        value = value_group or (match.group(rule.target_group) if match is not None else '') or reported
        encoding = rule.encoding_of_value() if value_group else None
        return cls(
            name=group(GroupType.NAME),
            value=value or '',
            filepath=filepath,
            rule=rule.id,
            evidence=rule.evidence.value if rule.evidence is not None else '',
            user=group(GroupType.USER),
            host=group(GroupType.HOST),
            kind=group(GroupType.KIND),
            encoding=encoding.value if encoding is not None else '',
        )
