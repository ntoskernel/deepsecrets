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
from typing import List

from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.response.base import BaseResponseBuilder
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.modes.iscan_mode import ScanMode


SRC_PATH_BASE_ID = 'SRCROOT'


class DojoSarifResponseBuilder(BaseResponseBuilder):

    report: SarifLog

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
        self.report.runs[0].original_uri_base_ids = (
            {
                SRC_PATH_BASE_ID: {
                    'uri': self.mode.config.workdir_path,
                },
            },
        )
        return self

    def _get_levels(self, rule: Rule):
        precision = 'very-high'
        security_severity = 'High'
        level = 'error'

        if rule.confidence >= 9:
            precision = 'very-high'
            security_severity = 'High'
            level = 'error'
        elif 9 > rule.confidence >= 6:
            precision = 'high'
            security_severity = 'High'
            level = 'error'
        elif 6 > rule.confidence >= 3:
            precision = 'medium'
            security_severity = 'High'
            level = 'error'
        elif 3 > rule.confidence >= 0:
            precision = 'low'
            security_severity = 'High'
            level = 'error'

        return {
            'precision': precision,
            'security_severity': security_severity,
            'level': level,
        }

    def _get_list_of_all_rules(self) -> List[ReportingDescriptor]:
        sarif_rules = []
        for _, ruleset in self.mode.rulesets.items():
            for rule in ruleset:
                sarif_rules.append(self._get_rule(rule))

        return sarif_rules

    def _get_rule(self, rule: Rule) -> ReportingDescriptor:
        levels = self._get_levels(rule)
        return ReportingDescriptor(
            id=rule.id,
            short_description={'text': rule.name},
            full_description={'text': rule.name},
            help={'text': rule.name},
            properties={
                'security-severity': levels.get('security_severity'),
                'precision': levels.get('precision'),
            },
            default_configuration={'level': levels.get('level')},
        )

    def build(self) -> SarifLog:  # type: ignore

        rules: set[Rule] = set()  # self._get_list_of_rules()

        for finding in self.findings:
            finding.choose_final_rule()
            region = self.get_region(finding=finding, masking=self.masking_enabled)
            context_region = self.get_context_region(finding=finding, masking=self.masking_enabled)

            rules.add(finding.final_rule)

            result = Result(
                rule_id=finding.final_rule.id,
                message=Message(text=f'Secret in code: ({finding.final_rule.name})'),
                locations=[
                    Location(
                        physical_location=PhysicalLocation(
                            artifact_location=ArtifactLocation(uri=finding.file.relative_path, uri_base_id='%SRCROOT%'),
                            region=region,
                            context_region=context_region,
                        )
                    )
                ],
            )

            self.report.runs[0].results.append(result)

        self.report.runs[0].tool.driver.rules = [self._get_rule(rule) for rule in rules]
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

        if masking:
            snippet = self._mask(snippet=snippet, detection=finding.detection)

        return Region(
            start_line=finding.start_line_number,
            end_line=finding.end_line_number,
            start_column=start_column,
            end_column=end_column,
            snippet=ArtifactContent(text=snippet),
        )
