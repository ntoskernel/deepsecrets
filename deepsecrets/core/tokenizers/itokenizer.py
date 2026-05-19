from abc import abstractmethod
from collections import namedtuple
from typing import List, NamedTuple, Optional

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import SemanticType, Token
from deepsecrets.core.utils.lifecycle_hooks import FileLifecycleHooks


class Tokenizer:
    tokens: List[Token]
    settings: NamedTuple
    lifecycle: FileLifecycleHooks

    last_offset_reported: float = 0

    def __init__(self, **kwargs) -> None:
        self.tokens = []
        Settings = namedtuple('Settings', kwargs.keys())  # type: ignore
        self.settings = Settings._make(kwargs.values())  # type: ignore
        self.lifecycle = None

    def add_lifecycle_hooks(self, lifecycle):
        self.lifecycle = lifecycle

    def on_new_offset_processed(self, new_offset: float):
        if self.lifecycle is None:
            return
        if new_offset - self.last_offset_reported < 0.01:
            return

        self.last_offset_reported = new_offset

        self.lifecycle.on_tokenization_progress(
            name=self.__class__.__name__,
            new_offset=round(new_offset, 2),
        )

    @abstractmethod
    def tokenize(self, file: File) -> List[Token]:
        pass

    def __hash__(self) -> int:  # pragma: nocover
        return hash(type(self))

    def __repr__(self) -> str:  # pragma: no cover
        return self.__class__.__name__

    def get_variables(self, tokens: Optional[List[Token]] = None) -> List[Token]:
        tokens = tokens if tokens is not None else self.tokens
        vars = []
        if len(tokens) == 0:
            return []

        for token in tokens:
            if token.semantic is None:
                continue

            if token.semantic.type != SemanticType.VARIABLE:
                continue

            vars.append(token)

        return vars
