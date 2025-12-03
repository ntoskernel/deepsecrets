from dataclasses import dataclass
from typing import List

from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers.semantic.language import Language


@dataclass
class TokenizedRegion:
    language: Language
    tokens: List[Token]
    stream: str
