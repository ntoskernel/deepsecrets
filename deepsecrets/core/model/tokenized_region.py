from dataclasses import dataclass
from typing import List

from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers.semantic.language import Language


@dataclass
class TokenizedRegion:
    language: Language

    tokens: List[Token]
    stream: str

    substitute_start_index: int
    substitute_end_index: int

    def __hash__(self):
        return hash((self.stream, self.substitute_start_index, self.substitute_end_index))

    def __eq__(self, other: 'TokenizedRegion'):
        if other.language != self.language:
            return False

        if other.stream != self.stream:
            return False

        if other.substitute_start_index != self.substitute_start_index:
            return False

        if other.substitute_end_index != self.substitute_end_index:
            return False

        return True
