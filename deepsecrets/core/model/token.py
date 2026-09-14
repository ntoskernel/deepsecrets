from __future__ import annotations

from enum import Enum, auto
from typing import Any, Dict, List, Optional, Type

from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.hashing import HashingAlgorithm
from deepsecrets.core.utils.hashing import get_hash


class SemanticType(Enum):
    VARIABLE = auto()


class Semantic:
    type: SemanticType
    payload: Any = None
    creds_probability: int

    def __init__(self, type: SemanticType, creds_probability: int = 0, payload: Any = None) -> None:
        self.type = type
        self.creds_probability = creds_probability
        self.payload = payload

    @property
    def name(self):
        return self.payload.context.name


class Token:
    content: str
    uncovered_content: List[str]
    span: List[int]
    file: 'File'
    type: List[Type]
    length: int
    hashed_values: Dict[HashingAlgorithm, str]
    semantic: Optional[Semantic]
    previous: Optional['Token']
    next: Optional['Token']

    def __init__(self, file: File, content: Optional[str] = None, span: Optional[List[int]] = None) -> None:
        self.file = file
        self.content = content
        self.span = span
        self.length = len(content) if self.content else 0
        self.hashed_values = {}
        self.previous = None
        self.next = None
        self.type: List[Type] = []  # type: ignore
        self.semantic = None
        self.uncovered_content = []

    def set_type(self, type: List[Type]) -> None:
        self.type = type  # type: ignore

    def val_hash(self) -> int:
        return hash(self.content)

    def calculate_hashed_value(self, algorithm: HashingAlgorithm) -> str:
        # cached per algorithm: rules for the same token length may use different algorithms
        if algorithm not in self.hashed_values:
            self.hashed_values[algorithm] = get_hash(payload=self.content, algorithm=algorithm)

        return self.hashed_values[algorithm]

    def __repr__(self) -> str:  # pragma: no cover
        if self.semantic is None and self.type is not None:
            return f'{self.content} | {self.type[0]}\n'

        out = f'======== VAR: {self.semantic.payload.context.name} = {self.content}'  # type: ignore
        if self.type is not None and len(self.type) > 0:
            out += f' | {self.type[0]}\n'

        return out
