from sarif_om import (
    SarifLog,
    Run,
    Tool,
    ToolComponent,
    ReportingDescriptor,
    ArtifactContent,
    Result,
    Region,
    Message,
    ArtifactLocation,
    PhysicalLocation,
    Location,
)
from deepsecrets.config import SCANNER_NAME, SCANNER_URL, SCANNER_VERSION
from deepsecrets.core.model import Finding
from typing import Dict

from deepsecrets.core.model.response.base import BaseResponseBuilder


class DojoSarifResponseBuilder(BaseResponseBuilder):

    def _get_levels(self, finding: Finding):
        if finding.final_rule.confidence > 5:
            precision = 'high'
            security_severity = 'High'
            level = 'error'
        elif finding.final_rule.confidence > 0:
            precision = 'medium'
            security_severity = 'High'
            level = 'error'
        else:
            precision = 'low'
            security_severity = 'Medium'
            level = 'warning'

        return {
            'precision': precision,
            'security_severity': security_severity,
            'level': level,
        }

    def build(self) -> SarifLog:  # type: ignore

        report = SarifLog(
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

        sarif_rules: Dict[str, ReportingDescriptor] = {}

        for finding in self.findings:

            finding.choose_final_rule()
            levels = self._get_levels(finding=finding)

            rule = ReportingDescriptor(
                id=finding.final_rule.id,
                short_description={'text': finding.final_rule.name},
                full_description={'text': finding.final_rule.name},
                help={'text': finding.final_rule.name},
                properties={
                    'security_severity': levels.get('security_severity'),
                    'precision': levels.get('precision'),
                },
                default_configuration={'level': levels.get('level')},
            )

            sarif_rules[finding.final_rule.id] = rule

            region = self.get_region(finding=finding, masking=self.masking_enabled)
            context_region = self.get_context_region(finding=finding, masking=self.masking_enabled)

            result = Result(
                rule_id=finding.final_rule.id,
                message=Message(text=f'Secret in code ({finding.final_rule.name})'),
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

            report.runs[0].results.append(result)

        report.runs[0].tool.driver.rules = [rule for rule in sarif_rules.values()]
        return report

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

    def get_region(self, finding: 'Finding', masking: bool = True):

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
