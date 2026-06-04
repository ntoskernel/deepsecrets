from __future__ import annotations

from hashlib import sha256
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.rule import Rule

from deepsecrets.config import MAX_LINE_LENGTH_FOR_CONTEXT


class Finding(BaseModel):
    file: Optional['File'] = Field(default=None)
    rules: List[Rule] = Field(default=[])
    detection: str
    full_line: Optional[str] = Field(default=None)
    full_line_partial: bool = Field(default=False)
    start_line_number: Optional[int] = Field(default=None)
    end_line_number: Optional[int] = Field(default=None)
    start_offset: int
    end_offset: int
    reason: str = Field(default='')
    final_rule: Optional[Rule] = Field(default=None)
    internal_score: Optional[dict] = Field(default_factory=dict)
    _mapped_on_file: bool = PrivateAttr(default=False)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def map_on_file(self, relative_start: int, file: Optional['File'] = None) -> None:
        if self._mapped_on_file:
            return

        if file is None and self.file is None:
            raise Exception('No file to match on')
        if self.file is None:
            self.file = file

        self.start_offset += relative_start
        self.end_offset += relative_start

        self.start_line_number = self.file.get_line_number(self.start_offset)
        self.end_line_number = self.file.get_line_number(self.end_offset)

        if not self.full_line:
            self._populate_full_line()

        self._mapped_on_file = True

    def _populate_full_line(self):
        self.full_line_partial = False
        if self.file.get_line_length(self.start_line_number) <= MAX_LINE_LENGTH_FOR_CONTEXT:
            self.full_line = self.file.get_line_contents(self.start_line_number)
            return

        self.full_line_partial = True
        return
        # TODO: boundaries = self._get_context_boundaries()

    def get_reason(self) -> str:
        if self.final_rule is None:
            self.choose_final_rule()

        return f'{self.final_rule.name} | {self.get_fingerprint()}'  # type: ignore

    def get_fingerprint(self) -> str:
        return sha256(self.detection.encode('utf-8')).hexdigest()[23:33]

    def get_partial_fingerprint(self) -> str:
        var_name = self.internal_score.get('var', '')
        base = f'{self.file.relative_path}|{var_name}|{self.detection}'
        return sha256(base.encode('utf-8')).hexdigest()

    def choose_final_rule(self) -> None:
        self.final_rule = sorted(self.rules, key=lambda r: r.confidence, reverse=True)[0]

    def __hash__(self) -> int:  # pragma: nocover
        if not self.file:
            raise Exception()

        return hash(f'{self.file.path}{self.detection}{self.start_offset}{self.end_offset}')

    def get_id(self) -> int:
        return int(str(abs(self.__hash__()))[:9])

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return False

        if other.file and self.file:
            if other.file.path != self.file.path:
                return False

        if other.detection and self.detection:
            if other.detection != self.detection:
                return False

        if other.start_offset and self.start_offset:
            if other.start_offset != self.start_offset:
                return False

        if other.end_offset and self.end_offset:
            if other.end_offset != self.end_offset:
                return False

        return True

    def merge(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return False

        if other != self:
            return False

        self.rules.extend(other.rules)
        self.rules = list(set(self.rules))

        return True
