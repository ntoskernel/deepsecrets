from dataclasses import dataclass
from typing import List, Optional
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding


@dataclass
class PerFileAnalysisResult:
    internal_task_id: int
    findings: List[Finding]
    errors: List[str]

    # ONLY FOR BENCHMARKING MODE
    _file: Optional[File] = None
