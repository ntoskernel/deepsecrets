from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, RootModel


class SecretPointer(BaseModel):
    found: bool
    secret_id: Optional[int] = None
    line_number: Optional[int] = None
    line_offset: Optional[int] = None
    is_valid: bool
    detection: Optional[str] = None
    internal_score: Optional[str] = None
    context: Optional[str] = None
    rule_id: Optional[str] = None
    is_extra: Optional[bool] = Field(default=False)


class FileVerificationResult(BaseModel):
    checked: bool = Field(default=False)
    all_found: bool = Field(default=True)
    file_identifier: str

    sb_secrets_count: int = Field(default=0)
    sb_valid_secrets_count: int = Field(default=0)
    sb_false_secrets_count: int = Field(default=0)

    not_found_valid_secret_ids: List[int] = Field(default_factory=list)
    not_found_false_secret_ids: List[int] = Field(default_factory=list)
    found_valid_secret_ids: List[int] = Field(default_factory=list)
    found_false_secret_ids: List[int] = Field(default_factory=list)

    extra_secrets_count: int = 0
    updated_ts: Optional[datetime] = None
    report: Dict[int, SecretPointer] = Field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.file_identifier)

    def __eq__(self, value: object) -> bool:
        return value.file_identifier == self.file_identifier


class VerificationsReportFile(RootModel):
    root: Dict[str, FileVerificationResult]
