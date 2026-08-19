from dataclasses import dataclass
from typing import List, Set

from sarif_om import (
    SarifLog,
    Run,
    Tool,
    ToolComponent,
    ReportingDescriptor,
    Result,
    Message,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    ArtifactContent,
    Region,
)
from deepsecrets.config import SCANNER_NAME, SCANNER_URL, SCANNER_VERSION

from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.response.base import BaseResponseBuilder
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.modes.iscan_mode import ScanMode

SRC_PATH_BASE_ID = 'SRCROOT'


@dataclass
class TierAwareSarifRuleMeta:
    id: str
    payload: dict

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, value: 'object') -> bool:
        if not isinstance(value, TierAwareSarifRuleMeta):
            return False

        if value.id != self.id:
            return False

        return True


class DojoSarifResponseBuilder(BaseResponseBuilder):

    report: SarifLog

    def _get_tier(self, confidence: int):
        confidence_tiers = {
            (9, float('inf')): {
                'suffix': '-VERY-HIGH',
                'precision': 'very-high',
                'severity': '10.00',
                'label': 'Very High',
            },
            (6, 9): {
                'suffix': '-HIGH',
                'precision': 'high',
                'severity': '9.70',
                'label': 'High',
            },
            (3, 6): {
                'suffix': '-MEDIUM',
                'precision': 'medium',
                'severity': '9.40',
                'label': 'Medium',
            },
            (float('-inf'), 3): {
                'suffix': '-LOW',
                'precision': 'low',
                'severity': '9.10',
                'label': 'Low',
            },
        }

        for (start, end), value in confidence_tiers.items():
            if start <= confidence < end:
                return value

    def _sarif_rule_meta_from_rule(self, rule: Rule) -> TierAwareSarifRuleMeta:

        base_rule_id = rule.id
        base_description = rule.name

        tier = self._get_tier(rule.confidence)
        suffix = tier.get('suffix') if rule.is_dynamic_confidence is True else ''

        return TierAwareSarifRuleMeta(
            id=f'{base_rule_id}{suffix}',
            payload={
                'shortDescription': {'text': f'{base_description} ({tier.get("label")} Confidence)'},
                'properties': {'precision': tier.get("precision"), 'security-severity': tier.get("severity")},
            },
        )

    def __init__(self) -> None:
        super().__init__()
        self.report = SarifLog(
            schema_uri='https://json.schemastore.org/sarif-2.1.0.json',
            version='2.1.0',
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name=SCANNER_NAME,
                            semantic_version=SCANNER_VERSION,
                            information_uri=SCANNER_URL,
                            rules=[],
                        )
                    ),
                    results=[],
                )
            ],
        )

    def with_current_mode(self, mode: ScanMode):
        super().with_current_mode(mode)
        self.report.runs[0].original_uri_base_ids = {
            SRC_PATH_BASE_ID: {
                'uri': self.mode.config.workdir_path,
            },
        }
        return self

    def _convert_rules(self, rules: Set[TierAwareSarifRuleMeta]) -> List[ReportingDescriptor]:
        return [
            ReportingDescriptor(
                id=rule_meta.id,
                short_description=rule_meta.payload.get('shortDescription'),
                properties=rule_meta.payload.get('properties'),
            )
            for rule_meta in rules
        ]

    def build(self) -> SarifLog:  # type: ignore

        rules: List[Rule] = list()

        for finding in self.findings:
            finding.choose_final_rule()
            region = self.get_region(finding=finding, masking=self.masking_enabled)
            context_region = self.get_context_region(finding=finding, masking=self.masking_enabled)

            rules.append(finding.final_rule)
            rule_meta = self._sarif_rule_meta_from_rule(finding.final_rule)

            result = Result(
                rule_id=rule_meta.id,
                level='error',
                properties={
                    'confidence': finding.final_rule.confidence,
                },
                message=Message(
                    text=f'[Confidence {finding.final_rule.confidence}/10] Secret in code: {finding.final_rule.name}'
                ),
                locations=[
                    Location(
                        physical_location=PhysicalLocation(
                            artifact_location=ArtifactLocation(uri=finding.file.relative_path, uri_base_id='%SRCROOT%'),
                            region=region,
                            context_region=context_region,
                        )
                    )
                ],
                partial_fingerprints={
                    'dsfpx/v1': finding.get_partial_fingerprint(),
                },
            )

            self.report.runs[0].results.append(result)

        sarif_rules = self._convert_rules(set([self._sarif_rule_meta_from_rule(rule) for rule in rules]))
        self.report.runs[0].tool.driver.rules = sarif_rules
        return self.report

    def get_context_region(self, finding: Finding, masking: bool = True):

        start_column = finding.file.get_column_number(position=finding.start_offset)
        end_column = finding.file.get_column_number(position=finding.end_offset)

        boundaries, _ = self._get_context_boundaries(finding, start_column, end_column)
        base_offset = finding.file.get_line_start_offset(finding.start_line_number)
        snippet = finding.file.content[base_offset + boundaries[0] : base_offset + boundaries[1]]

        if masking:
            snippet = self._mask(snippet=snippet, detection=finding.detection)

        return Region(
            start_line=finding.start_line_number,
            end_line=finding.end_line_number,
            start_column=boundaries[0],
            end_column=boundaries[1],
            snippet=ArtifactContent(text=snippet),
        )

    def get_region(self, finding: Finding, masking: bool = True):

        start_column = finding.file.get_column_number(position=finding.start_offset)
        end_column = finding.file.get_column_number(position=finding.end_offset)

        snippet = finding.detection

        if masking is True:
            snippet = self._mask(snippet=snippet, detection=finding.detection)

        return Region(
            start_line=finding.start_line_number,
            end_line=finding.end_line_number,
            start_column=start_column,
            end_column=end_column,
            snippet=ArtifactContent(text=snippet),
        )
