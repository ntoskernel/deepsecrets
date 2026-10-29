from __future__ import annotations

from hashlib import sha256
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.rule import Rule

from deepsecrets.config import MAX_LINE_LENGTH_FOR_CONTEXT


class Finding(BaseModel):
    """A reported span. Engines create it with offsets relative to their token; map_on_file() makes them file offsets
    and fills in the lines. Findings of one span from several engines or passes are merged into one (FindingMerger),
    which keeps one rule per id and reports the final rule (choose_final_rule)."""

    file: Optional['File'] = Field(default=None)
    rules: List[Rule] = Field(default=[])
    detection: str
    start_offset: int
    end_offset: int
    start_line_number: Optional[int] = Field(default=None)
    end_line_number: Optional[int] = Field(default=None)
    # the line of the finding, unless it is longer than MAX_LINE_LENGTH_FOR_CONTEXT (then full_line_partial is set)
    full_line: Optional[str] = Field(default=None)
    full_line_partial: bool = Field(default=False)
    reason: str = Field(default='')
    final_rule: Optional[Rule] = Field(default=None)
    # how the engine scored it; 'var', the variable's name, is part of the partial fingerprint
    internal_score: Optional[dict] = Field(default_factory=dict)
    # a regex candidate its evaluation rejected: reported only at --confidence-level all, with confidence 0
    rejected: bool = Field(default=False)
    # what sort of finding it is: weak-password, publishable, test-context (core/helpers/finding_tags.py). A tag never
    # changes what is reported; --exclude-tags filters on it, and SARIF carries it
    tags: List[str] = Field(default_factory=list)
    _mapped_on_file: bool = PrivateAttr(default=False)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def map_on_file(self, relative_start: int, file: Optional['File'] = None) -> None:
        """Turns token-relative offsets into file offsets, once. The finding's own file, when it has one, wins over
        `file`."""
        if self._mapped_on_file:
            return
        if self.file is None:
            if file is None:
                raise Exception('No file to match on')
            self.file = file

        self.start_offset += relative_start
        self.end_offset += relative_start
        self.start_line_number = self.file.get_line_number(self.start_offset)
        self.end_line_number = self.file.get_line_number(self.end_offset)
        if not self.full_line:
            self._populate_full_line()
        self._mapped_on_file = True

    def _populate_full_line(self) -> None:
        self.full_line_partial = self.file.get_line_length(self.start_line_number) > MAX_LINE_LENGTH_FOR_CONTEXT
        if not self.full_line_partial:
            self.full_line = self.file.get_line_contents(self.start_line_number)

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)

    def get_reason(self) -> str:
        if self.final_rule is None:
            self.choose_final_rule()
        return f'{self.final_rule.name} | {self.get_fingerprint()}'  # type: ignore

    def get_fingerprint(self) -> str:
        """A short digest of the detection alone."""
        return sha256(self.detection.encode('utf-8')).hexdigest()[23:33]

    def get_partial_fingerprint(self) -> str:
        """SARIF's dsfpx/v1: the relative path, the variable's name and the detection, so a finding keeps its identity
        when lines move or its tier changes."""
        var_name = self.internal_score.get('var', '')
        return sha256(f'{self.file.relative_path}|{var_name}|{self.detection}'.encode('utf-8')).hexdigest()

    def choose_final_rule(self) -> None:
        # highest confidence first; a tie goes to the earlier rule in its ruleset, then the id, never to set order
        self.final_rule = min(self.rules, key=lambda r: (-r.confidence, r.rank, r.id))

    def __hash__(self) -> int:  # pragma: nocover
        """The merge key: one file, one detection, one span."""
        if not self.file:
            raise Exception()
        return hash(f'{self.file.path}{self.detection}{self.start_offset}{self.end_offset}')

    def get_id(self) -> int:
        return int(str(abs(self.__hash__()))[:9])

    def __eq__(self, other: Any) -> bool:
        """Two findings are equal unless a field both of them set differs: the file's path, the detection, either
        offset. An unset field (no file, an empty detection, offset 0) matches anything."""
        if not isinstance(other, Finding):
            return False
        if self.file and other.file and self.file.path != other.file.path:
            return False
        pairs = (
            (self.detection, other.detection),
            (self.start_offset, other.start_offset),
            (self.end_offset, other.end_offset),
        )
        return all(not (mine and theirs) or mine == theirs for mine, theirs in pairs)

    def merge(self, other: Any) -> bool:
        """Takes an equal finding's rules and tags into this one; False, and nothing changes, for any other.

        One rule per id, in insertion order. The same rule reached through two passes keeps the first copy seen,
        except that a kept finding's copy beats a rejected candidate's, and a static copy (a regex match the semantic
        engine corroborated) beats a dynamic one. The merged finding is rejected only when both were, and carries the
        tags of both."""
        if not isinstance(other, Finding) or other != self:
            return False

        first, second = (other, self) if self.rejected and not other.rejected else (self, other)
        best = {rule.id: rule for rule in first.rules}
        for rule in second.rules:
            kept = best.get(rule.id)
            if kept is None or (kept.is_dynamic_confidence and not rule.is_dynamic_confidence):
                best[rule.id] = rule
        self.rules = list(best.values())
        self.rejected = self.rejected and other.rejected
        self.tags = list(dict.fromkeys([*self.tags, *other.tags]))
        return True
