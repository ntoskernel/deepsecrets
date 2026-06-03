import regex as re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Rule(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = Field(default=True)
    confidence: int = Field(default=10)
    is_dynamic_confidence: bool = Field(default=False)
    applicable_file_patterns: List[re.Pattern] = Field(default=[])

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @model_validator(mode='before')
    @classmethod
    def fill_confidence_and_file_patterns(cls, values: Dict) -> Dict:
        file_patterns = values.get('applicable_file_patterns', [])
        if len(file_patterns) > 0:
            pattеrns = [re.compile(p) for p in file_patterns]
            values['applicable_file_patterns'] = pattеrns

        if values.get('confidence', None) is None and values.get('id') is not None:
            values['confidence'] = 10

        return values

    def __hash__(self) -> int:  # pragma: nocover
        return hash(self.id)

    def __eq__(self, other: Any):
        if not isinstance(other, Rule):
            return False

        if self.id != other.id:
            return False

        return True
