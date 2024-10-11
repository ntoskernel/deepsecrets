from __future__ import annotations

from hashlib import sha256
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, PrivateAttr

from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.rule import Rule

import sarif_om as om
from deepsecrets.config import SCANNER_NAME, SCANNER_URL, SCANNER_VERSION

class Finding(BaseModel):
    file: Optional['File'] = Field(default=None)
    rules: List[Rule] = Field(default=[])
    detection: str
    full_line: Optional[str] = Field(default=None)
    linum: Optional[int] = Field(default=None)
    start_pos: int
    end_pos: int
    start_column: Optional[int]
    end_column: Optional[int]
    reason: str = Field(default='')
    final_rule: Optional[Rule] = Field(default=None)
    _mapped_on_file: bool = PrivateAttr(default=False)

    def map_on_file(self, relative_start: int, file: Optional['File'] = None) -> None:
        if self._mapped_on_file:
            return

        if file is None and self.file is None:
            raise Exception('No file to match on')
        if self.file is None:
            self.file = file

        self.start_column = self.start_pos
        self.end_column = self.end_pos

        self.start_pos += relative_start
        self.end_pos += relative_start
        self.linum = self.file.get_line_number(self.end_pos)

        if not self.full_line:
            self.full_line = self.file.get_line_contents(self.linum)
        self._mapped_on_file = True

    def get_reason(self) -> str:
        if self.final_rule is None:
            self.choose_final_rule()

        return f'{self.final_rule.name} | {self.get_fingerprint()}'  # type: ignore

    def get_fingerprint(self) -> str:
        return sha256(self.detection.encode('utf-8')).hexdigest()[23:33]

    class Config:
        arbitrary_types_allowed = True

    def choose_final_rule(self) -> None:
        self.final_rule = sorted(
            self.rules, key=lambda r: r.confidence,
            reverse=True
        )[0]

    def __hash__(self) -> int:  # pragma: nocover
        if not self.file:
            raise Exception()

        return hash(f'{self.file.path}{self.detection}{self.start_pos}{self.end_pos}')

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return False

        if other.file and self.file:
            if other.file.path != self.file.path:
                return False

        if other.detection and self.detection:
            if other.detection != self.detection:
                return False

        if other.start_pos and self.start_pos:
            if other.start_pos != self.start_pos:
                return False

        if other.end_pos and self.end_pos:
            if other.end_pos != self.end_pos:
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


class FindingMerger:
    all: List[Finding]

    def __init__(self, full_list: List[Finding]) -> None:
        self.all = full_list

    def merge(self) -> List[Finding]:
        interm_dict: Dict[int, Finding] = {}

        for elem in self.all:
            hash = elem.__hash__()
            if hash not in interm_dict:
                interm_dict[hash] = elem

            interm_dict[hash].merge(elem)

        return list(interm_dict.values())


class FindingResponse:
    @classmethod
    def from_list(cls, list: List[Finding], disable_masking: bool = False) -> Dict[str, List[Dict]]:
        resp: Dict[str, List[Dict]] = {}
        for finding in list:
            if finding.file is None:
                continue

            if finding.file.path not in resp:
                resp[finding.file.path] = []
            
            resp_finding = FindingApiModel.from_finding(finding)
            
            if not disable_masking:

                resp_finding.line = resp_finding.line.replace(resp_finding.string, "*" * len(resp_finding.string))
                resp_finding.string = "*" * len(resp_finding.string)

            resp[finding.file.path].append(resp_finding.dict())

        return resp

    @classmethod
    def sarif_from_list(cls, list: List[Finding], disable_masking: bool = False) -> om.SarifLog:
        
        report = om.SarifLog(
            schema_uri="https://json.schemastore.org/sarif-2.1.0.json",
            version="2.1.0",
            runs=[
                om.Run(
                    tool=om.Tool(
                        driver=om.ToolComponent(
                            name=SCANNER_NAME,
                            semantic_version=SCANNER_VERSION,
                            information_uri=SCANNER_URL,
                            rules=[]
                        )
                    ),
                    results=[]
                )
            ]
        )

        rules: Dict[str, om.ReportingDescriptor] = {}

        for finding in list:

            finding.choose_final_rule()

            if finding.final_rule.confidence > 5 :
                precision = "high"
                security_severity = "High"
                level = "error"
            elif finding.final_rule.confidence > 0:
                precision = "medium"
                security_severity = "High"
                level = "error"
            else:
                precision = "low"
                security_severity = "Medium"
                level = "warning"

            rule = om.ReportingDescriptor(
                id=finding.final_rule.id,
                short_description={
                    "text": finding.final_rule.name
                },
                full_description={
                    "text": finding.final_rule.name
                },
                help={
                    "text": finding.final_rule.name
                },
                properties={
                    "security_severity": security_severity,
                    "precision": precision
                },
                default_configuration={"level": level},
            )

            rules[finding.final_rule.id] = rule

        report.runs[0].tool.driver.rules = [rule for rule in rules.values()]

        for finding in list:

            finding.choose_final_rule()

            if finding.start_column > 50 :
                context_start_pos = finding.start_column - 50
            else:
                context_start_pos = 0

            if finding.end_column < len(finding.full_line) - 50 :
                context_end_pos = finding.end_column + 50
            else:
                context_end_pos = len(finding.full_line)

            if len(finding.detection) > 50:
                detection_masked = "*" * 50
            else:
                detection_masked = "*" * len(finding.detection)


            context_text = finding.full_line[context_start_pos:context_end_pos]
            context_text_masked = finding.full_line[context_start_pos:finding.start_column] + detection_masked + finding.full_line[finding.end_column:context_end_pos]

            if disable_masking :
                region = om.Region(
                    start_line=finding.linum,
                    start_column=finding.start_column,
                    end_column=finding.end_column,
                    snippet=om.ArtifactContent(text=finding.detection)
                )
                context_region=om.Region(
                    start_line=finding.linum,
                    snippet=om.ArtifactContent(text=context_text)
                )
            else:
                region = om.Region(
                    start_line=finding.linum,
                    start_column=finding.start_column,
                    end_column=finding.end_column
                )
                context_region=om.Region(
                    start_line=finding.linum,
                    snippet=om.ArtifactContent(text=context_text_masked)
                )

            result = om.Result(
                rule_id=finding.final_rule.id,
                message=om.Message(
                    text=f"Secret in code ({finding.final_rule.name})"
                ),
                locations=[
                    om.Location(
                        physical_location=om.PhysicalLocation(
                            artifact_location=om.ArtifactLocation(
                                uri=finding.file.relative_path,
                                uri_base_id="%SRCROOT%"
                            ),
                            region=region,
                            context_region=context_region
                        )
                    )
                ]
            )

            report.runs[0].results.append(result)

        return report

class FindingApiModel(BaseModel):
    line: str
    string: str
    line_number: int
    rule: str
    reason: str
    confidence: int
    fingerprint: str

    @classmethod
    def from_finding(cls, finding: Finding) -> FindingApiModel:
        finding.choose_final_rule()
        return FindingApiModel(
            line=finding.full_line,
            string=finding.detection,
            line_number=finding.linum,
            rule=finding.final_rule.id,
            reason=finding.get_reason(),
            confidence=finding.final_rule.confidence,
            fingerprint=finding.get_fingerprint(),
        )
