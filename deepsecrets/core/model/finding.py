from __future__ import annotations

from hashlib import sha256
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, PrivateAttr

from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.model.sarif import (
    Sarif,
    Run,
    Tool,
    Rule as SarifRule,
    RuleShortDescription,
    RuleFullDescription,
    RuleHelp,
    RuleProperties,
    RuleDefaultConfiguration,
    Result,
    LevelEnum,
    PrecisionEnum,
    SecuritySeverityEnum,
    Message,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    Region,
    RegionSnippet
)

class Finding(BaseModel):
    file: Optional['File'] = Field(default=None)
    rules: List[Rule] = Field(default=[])
    detection: str
    full_line: Optional[str] = Field(default=None)
    linum: Optional[int] = Field(default=None)
    start_pos: int
    end_pos: int
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
    def from_list(cls, list: List[Finding]) -> Dict[str, List[Dict]]:
        resp: Dict[str, List[Dict]] = {}
        for finding in list:
            if finding.file is None:
                continue

            if finding.file.path not in resp:
                resp[finding.file.path] = []

            resp[finding.file.path].append(FindingApiModel.from_finding(finding).dict())
        return resp

    @classmethod
    def sarif_from_list(cls, list: List[Finding]) -> Dict:
        
        resp: Dict = {}

        report = Sarif(
            runs=[
                Run(
                    tool=Tool(
                        rules=[]
                    ),
                    results=[]
                )
            ]
        )

        rules: Dict[str, SarifRule] = {}
        results: List[Result] = []

        for finding in list:

            finding.choose_final_rule()

            rule = SarifRule(
                id=finding.final_rule.id,
                shortDescription=RuleShortDescription(
                    text=finding.final_rule.name
                ),
                fullDescription=RuleFullDescription(
                    text=finding.final_rule.name
                ),
                help=RuleHelp(
                    text=finding.final_rule.name
                )
            )

            if finding.final_rule.confidence > 5 :
                rule.properties = RuleProperties(
                    precision=PrecisionEnum.high,
                    security_severity=SecuritySeverityEnum.high
                )
                rule.defaultConfiguration = RuleDefaultConfiguration(
                    level=LevelEnum.error
                )
            elif finding.final_rule.confidence > 0:
                rule.properties = RuleProperties(
                    precision=PrecisionEnum.medium,
                    security_severity=SecuritySeverityEnum.high
                )
                rule.defaultConfiguration = RuleDefaultConfiguration(
                    level=LevelEnum.error
                )
            else:
                rule.properties = RuleProperties(
                    precision=PrecisionEnum.low,
                    security_severity=SecuritySeverityEnum.medium
                )
                rule.defaultConfiguration = RuleDefaultConfiguration(
                    level=LevelEnum.warning
                )

            rules[finding.final_rule.id] = rule

        report.runs[0].tool.driver.rules = [rule for rule in rules.values()]

        for finding in list:

            finding.choose_final_rule()

            result = Result(
                ruleId=finding.final_rule.id,
                message=Message(
                    text=f"Secret in code ({finding.final_rule.name})"
                ),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            artifactLocation=ArtifactLocation(
                                uri=finding.file.relative_path
                            ),
                            region=Region(
                                startLine=finding.linum,
                                snippet=RegionSnippet(
                                    text=finding.full_line.replace(finding.detection, len(finding.detection)*"*")
                                )
                            )
                        )
                    )
                ]
            )

            results.append(result)
        
        report.runs[0].results = results

        return report.dict()

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
