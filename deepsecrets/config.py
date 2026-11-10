import logging
from typing import Dict, List, Optional, Sequence, Type

from pydantic import BaseModel
from deepsecrets import console
from deepsecrets.core.utils.cpu import CpuHelper

from deepsecrets.core.utils.exceptions import FileNotFoundException
from deepsecrets.core.utils.fs import get_abspath, path_exists
from deepsecrets.core.utils.multiprocessing_setup import default_start_method

FALLBACK_PROCESS_COUNT = 4

# The confidence tiers, by the lowest confidence each holds: a finding is in the highest tier whose floor it reaches.
# The one table both the SARIF tiers (the rule-id suffix, DojoSarifResponseBuilder) and --confidence-level read, so the
# two cannot disagree. LOW 0-4, MEDIUM 5, HIGH 6-8, VERY-HIGH 9-10: confidence 3 and 4 hold fewer secrets than 2 does,
# and 5 is the best-F1 cut (docs/private/research/2.3-design.md, P3)
TIER_FLOORS = {'low': 0, 'medium': 5, 'high': 6, 'very-high': 9}
# S106, a weak value under a name people choose a value for, has no value evidence: its confidence is the name's alone,
# so it stays in the LOW tier. The order among S106 findings survives up to this cap (2.3 design, P2)
WEAK_VALUE_MAX_CONFIDENCE = TIER_FLOORS['medium'] - 1
# A variable in recorded traffic (VCR cassettes, session recordings, HAR files) is most often a per-response value: a
# CSRF token, a session id, a request signature. S105 stays reported there, in the LOW tier (judging-for-2.4.md)
RECORDED_TRAFFIC_MAX_CONFIDENCE = TIER_FLOORS['medium'] - 1
# --confidence-level: the lowest confidence a reported finding may have. 'all' also reports the regex candidates their
# evaluation rejected (confidence 0); 'low', the default, reports every finding the scanner keeps
CONFIDENCE_LEVELS = {'all': None, **TIER_FLOORS}
# the confidences a finding can have, and the values --min-confidence takes
CONFIDENCE_RANGE = range(0, 11)
DEFAULT_CONFIDENCE_LEVEL = 'low'

# files larger than this many bytes get the shallow analysis: the regex rules and the cheap variable search, no lexer.
# On SecretBench the lexer found 12 of its 21 unique secrets in smaller files and the other 9 only in files of 1 MB
# or more (minified JavaScript, one YAML file), while files over 250 KB took two thirds of its time.
DEFAULT_DEEP_MAX_SIZE = 250_000


def deep_analysis(size: int, deep_max_size: int) -> bool:
    """Whether a file of `size` bytes gets the full analysis, lexer included. `deep_max_size` 0 or less: every file."""
    return deep_max_size <= 0 or size <= deep_max_size


SCANNER_NAME = "DeepSecrets"
SCANNER_VERSION = "2.2.0"
SCANNER_URL = "https://github.com/ntoskernel/deepsecrets"

MAX_LINE_LENGTH_FOR_CONTEXT = 300


class Output(BaseModel):
    type: str
    path: str


class Config:
    """One scan's settings. The CLI builds a fresh one for every parse (KI-CLI-12), and ScanMode takes it as a
    parameter. `workdir_path` and `output` have no default on purpose: a library caller must call set_workdir() and
    assign `output` before building a scan mode, and one that forgets fails with AttributeError instead of scanning an
    empty path (KI-CLI-10)."""

    workdir_path: str
    output: Output

    def __init__(self) -> None:
        # what to scan, and with which engines and rule files (ruleset builder -> absolute paths)
        self.engines: List[Type] = []
        self.rulesets: Dict[Type, List[str]] = {}
        self.global_exclusion_paths: List[str] = []
        # --oneshot: one file instead of a directory (benchmarking)
        self.oneshot_path: Optional[str] = None
        # bytes; 0 means no limit
        self.max_file_size = 0
        # files above this many bytes get no lexer (deep_analysis); 0 means every file gets it
        self.deep_max_size = DEFAULT_DEEP_MAX_SIZE

        # what to report
        self.confidence_level = DEFAULT_CONFIDENCE_LEVEL
        # --min-confidence: a floor of its own, in place of the level's
        self.min_confidence: Optional[int] = None
        # --exclude-tags: findings that carry any of these are not reported (core/helpers/finding_tags.py)
        self.excluded_tags: List[str] = []
        self.disable_masking = False
        self.report_diagnostics = False
        self.return_code_if_findings = False

        # how to run
        self.process_count = FALLBACK_PROCESS_COUNT
        self.mp_context = default_start_method()
        # no live terminal UI and no progress manager; the CLI turns it on in CI and when output is not a terminal
        self.ci_mode = False
        # stored and not read yet (KI-CLI-28)
        self.verbose = False
        self.logging_level = logging.INFO
        self._benchmarking_mode = False

    def set_verbose(self, verbose: bool) -> None:
        self.verbose = verbose

    def set_logging_level(self, level: int) -> None:
        self.logging_level = level

    def _set_benchmarking_mode(self, mode: bool) -> None:
        self._benchmarking_mode = mode

    def set_disable_masking(self, state: bool) -> None:
        self.disable_masking = state

    def set_report_diagnostics(self, state: bool) -> None:
        self.report_diagnostics = state

    def set_confidence_level(self, level: str) -> None:
        if level not in CONFIDENCE_LEVELS:
            raise ValueError(f'unknown confidence level {level}')
        self.confidence_level = level

    def set_min_confidence(self, minimum: Optional[int]) -> None:
        """A confidence floor from 0 to 10 that replaces the level's; None keeps the level's."""
        if minimum is not None and minimum not in CONFIDENCE_RANGE:
            raise ValueError(f'a minimum confidence is {CONFIDENCE_RANGE[0]} to {CONFIDENCE_RANGE[-1]}')
        self.min_confidence = minimum

    def set_excluded_tags(self, tags: Optional[Sequence[str]]) -> None:
        self.excluded_tags = list(dict.fromkeys(tags or ()))

    def set_workdir(self, path: str) -> None:
        if not path_exists(path):
            raise FileNotFoundException(f'workdir_path path does not exist ({path})')
        self.workdir_path = get_abspath(path)

    def set_oneshot_path(self, path: Optional[str]) -> None:
        self.oneshot_path = path
        if path is not None:
            self.workdir_path = ''

    def set_max_file_size(self, size: int) -> None:
        self.max_file_size = size

    def set_deep_max_size(self, size: int) -> None:
        self.deep_max_size = size

    def set_mp_context(self, context: str) -> None:
        self.mp_context = context

    def set_ci_mode(self, enabled: bool) -> None:
        self.ci_mode = enabled

    def set_process_count(self, count: int) -> None:
        """`count` workers. For 0 or less: the CPU limit of the machine or its container, else FALLBACK_PROCESS_COUNT,
        and either is announced."""
        if count > 0:
            self.process_count = count
            return

        limit = CpuHelper().get_limit()
        self.process_count = limit if limit > 0 else FALLBACK_PROCESS_COUNT
        source = 'based on the [cyan]machine\'s CPU config[/cyan]' if limit > 0 else 'as a [yellow]fallback[/yellow]'
        console.print(
            f'[bold yellow]:warning: Process count[/bold yellow] was not specified. '
            f'Setting it to [bold magenta]{self.process_count}[/bold magenta] {source}'
        )

    def set_global_exclusion_paths(self, paths: List[str]) -> None:
        """Adds exclusion files, each once, in the order given: the first file's patterns are matched first, so a skip
        reason names the same pattern on every run. 'disable' adds nothing."""
        for path in paths:
            if path == 'disable':
                continue
            if not path_exists(path):
                raise FileNotFoundException(f'global_exclusion_path does not exist ({path})')
            self.global_exclusion_paths.append(path)
        self.global_exclusion_paths = list(dict.fromkeys(self.global_exclusion_paths))

    def add_ruleset(self, builder: Type, paths: Sequence[str] = ()) -> None:
        """The rule files a ruleset builder reads, made absolute. Raises FileNotFoundException for a missing one."""
        self._validate_paths(paths)
        self.rulesets[builder] = [get_abspath(path) for path in paths]

    def _validate_paths(self, paths: Optional[Sequence[str]]) -> None:
        for path in paths or ():
            if not path_exists(path):
                raise FileNotFoundException(f'File {path} does not exist')
