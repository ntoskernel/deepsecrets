from dataclasses import dataclass, field
from typing import List

from deepsecrets.core.model.token import Token
from deepsecrets.core.utils.string import StringUtils
import regex as re


number_pattern = re.compile(r'\b\d+\b')
hex_color = re.compile(r'#(?:[0-9a-fA-F]{3}){1,2}\b')


@dataclass
class Context:
    name: str
    value: str
    filepath: str

    name_parts: List[str] = field(default_factory=list, repr=False)
    name_normalized: str = field(default_factory=str, repr=False)
    name_spaced: str = field(default_factory=str, repr=False)

    value_parts: List[str] = field(default_factory=list, repr=False)
    value_normalized: str = field(default_factory=str, repr=False)
    value_spaced: str = field(default_factory=str, repr=False)

    def __post_init__(self):
        self.name_spaced, self.name_normalized, self.name_parts = self.normalize_punctuation(self.name)
        self.value_spaced, self.value_normalized, self.value_parts = self.normalize_punctuation(
            self.value, split_camel_case=False
        )

    def normalize_punctuation(self, string: str, split_camel_case=True):
        normalized = string.replace(' ', '_')
        normalized = hex_color.sub('', normalized)
        normalized = number_pattern.sub('', normalized)
        normalized = (
            normalized.replace('-', ' ')
            .replace('_', ' ')
            .replace('.', ' ')
            .replace(':', ' ')
            .replace('=', ' ')
            .replace(';', ' ')
            .replace('#', ' ')
            .replace('/', ' ')
            .replace('@', ' ')
        )

        parts = []
        if split_camel_case:
            normalized = StringUtils.camel_case_divide(normalized)

        parts = normalized.split(' ')
        return ' '.join(parts), normalized.lower().replace(' ', ''), parts


class Variable:
    name: Token
    value: Token
    _context: Context = None
    span: List[int]
    found_by: 'VariableDetector'

    @property
    def context(self):
        if self._context is None:
            self._context = Context(
                name=self.name.content,
                value=self.value.content,
                filepath=self.name.file.path,
            )
        return self._context


class Region:
    span: List[int]
    found_by: 'RegionDetector'


from deepsecrets.core.tokenizers.helpers.semantic.var_detection.detector import (  # noqa: E402
    VariableDetector,
    RegionDetector,
)
