from dataclasses import field, dataclass
from typing import Dict, List, Optional, Sequence
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.rules.rule import Rule


@dataclass(frozen=True)
class AnalyzerBundle:
    """What every worker needs to analyse a file. Sent to each worker once, by the pool initializer.

    It crosses the process boundary by pickling, so every value must be picklable under `spawn`:
    no lambdas, closures or open handles, and only classes importable from a module.
    """

    workdir: str
    # engine name -> enabled
    engines: Dict[str, bool] = field(default_factory=dict)
    # ruleset name -> rules
    rulesets: Dict[str, Sequence[Rule]] = field(default_factory=dict)
    benchmarking_mode: bool = False


@dataclass
class PerFileAnalysisResult:
    internal_task_id: int
    findings: List[Finding]
    errors: List[str]

    processing_time_seconds: int = field(default=0)

    # ONLY FOR BENCHMARKING MODE
    _file: Optional[File] = None
