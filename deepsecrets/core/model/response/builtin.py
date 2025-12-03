from typing import Dict, List, Optional

from pydantic import BaseModel
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.response.base import BaseResponseBuilder


class FindingApiModel(BaseModel):
    line: Optional[str]
    string: str
    line_number: int
    start_line_number: int
    end_line_number: int
    rule: str
    reason: str
    confidence: int
    fingerprint: str
    file_start_offset: int
    file_end_offset: int

    @classmethod
    def from_finding(cls, finding: Finding) -> 'FindingApiModel':
        finding.choose_final_rule()
        return FindingApiModel(
            line=finding.full_line,
            string=finding.detection,
            line_number=finding.start_line_number,
            start_line_number=finding.start_line_number,
            end_line_number=finding.end_line_number,
            rule=finding.final_rule.id,
            reason=finding.get_reason(),
            confidence=finding.final_rule.confidence,
            fingerprint=finding.get_fingerprint(),
            file_start_offset=finding.start_offset,
            file_end_offset=finding.end_offset,
        )


class BuiltinFormatResponseBuilder(BaseResponseBuilder):

    def build(self) -> Dict[str, List[Dict]]:
        resp: Dict[str, List[Dict]] = {}
        for finding in self.findings:
            if finding.file is None:
                continue

            if finding.file.path not in resp:
                resp[finding.file.path] = []

            resp_finding = FindingApiModel.from_finding(finding)

            if self.masking_enabled:
                if resp_finding.line is not None:
                    resp_finding.line = resp_finding.line.replace(resp_finding.string, '*' * len(resp_finding.string))

                resp_finding.string = '*' * len(resp_finding.string)

            resp[finding.file.path].append(resp_finding.model_dump())

        return resp
