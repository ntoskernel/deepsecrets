from dataclasses import dataclass
from typing import List
from deepsecrets.core.model.finding import Finding


@dataclass
class PerFileAnalysisResult:
    internal_task_id: int
    findings: List[Finding]
    errors: List[str]
