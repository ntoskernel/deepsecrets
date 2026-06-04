from dataclasses import field, dataclass
from typing import List, Optional
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding


@dataclass
class PerFileAnalysisResult:
    internal_task_id: int
    findings: List[Finding]
    errors: List[str]

    processing_time_seconds: int = field(default=0)

    # ONLY FOR BENCHMARKING MODE
    _file: Optional[File] = None
