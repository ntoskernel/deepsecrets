from abc import abstractmethod
from typing import Any, List

from deepsecrets.config import MAX_LINE_LENGTH_FOR_CONTEXT
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.modes.iscan_mode import ScanMode


class BaseResponseBuilder:

    findings: List[Finding]
    mode: ScanMode
    masking_enabled: bool

    def __init__(self) -> None:
        self.masking_enabled = False

    def with_findings_list(self, findings: List[Finding]):
        self.findings = findings
        return self

    def with_current_mode(self, mode: ScanMode):
        self.mode = mode
        return self

    def with_masking_enabled(self, masking_enabled: bool):
        self.masking_enabled = masking_enabled
        return self

    @abstractmethod
    def build(self) -> Any:
        pass

    def _get_context_boundaries(self, finding: Finding, start_column: int, end_column: int):
        line_length = finding.file.get_line_length(finding.start_line_number)
        boundaries = [0, line_length]
        line_partial = False

        if line_length <= MAX_LINE_LENGTH_FOR_CONTEXT:
            return boundaries, line_partial

        line_partial = True
        boundaries[0] = int(start_column - (MAX_LINE_LENGTH_FOR_CONTEXT / 2))
        if boundaries[0] < 0:
            boundaries[0] = 0

        boundaries[1] = int(end_column + (MAX_LINE_LENGTH_FOR_CONTEXT / 2))
        if boundaries[1] > line_length:
            boundaries[1] = line_length

        return boundaries, line_partial

    def _mask(self, snippet: str, detection: str, symbol: str = '*'):
        length = len(detection)
        if length == 0:
            return snippet

        mask_len = (length + 1) // 2
        start_len = (length - mask_len) // 2

        masked_detection = detection[:start_len] + symbol * mask_len + detection[start_len + mask_len :]

        return snippet.replace(detection, masked_detection)
