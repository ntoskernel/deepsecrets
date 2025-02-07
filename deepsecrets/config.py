import logging
from typing import Dict, List, Type

from pydantic import BaseModel
from deepsecrets.core.utils.cpu import CpuHelper

from deepsecrets.core.utils.exceptions import FileNotFoundException
from deepsecrets.core.utils.fs import get_abspath, path_exists

FALLBACK_PROCESS_COUNT = 4

SCANNER_NAME = "DeepSecrets"
SCANNER_VERSION = "1.4.0"
SCANNER_URL = "https://github.com/ntoskernel/deepsecrets"


class Output(BaseModel):
    type: str
    path: str


class Config:
    logging_level: int
    workdir_path: str
    max_file_size: int = 0  # 0 means no limit
    mp_context: str = 'spawn'
    engines: List[Type] = []
    rulesets: Dict[Type, List[str]] = {}
    global_exclusion_paths: List[str] = []
    output: Output
    process_count: int
    return_code_if_findings: bool
    disable_masking: bool

    def __init__(self) -> None:
        self.engines = []
        self.rulesets = {}
        self.global_exclusion_paths = []
        self.return_code_if_findings = False
        self.disable_masking = False

        # equals to CPU count
        self.process_count = FALLBACK_PROCESS_COUNT
        self.logging_level = logging.INFO

    def set_logging_level(self, level: int):
        self.logging_level = level

    def set_disable_masking(self, state: bool):
        self.disable_masking = state

    def _set_path(self, path: str, field: str) -> None:
        if not path_exists(path):
            raise FileNotFoundException(f'{field} path does not exist ({path})')
        setattr(self, field, get_abspath(path))

    def set_workdir(self, path: str) -> None:
        self._set_path(path, 'workdir_path')

    def set_max_file_size(self, size: int) -> None:
        self.max_file_size = size

    def set_mp_context(self, context: str) -> None:
        self.mp_context = context
    
    def set_process_count(self, count: int) -> None:
        if count > 0:
            self.process_count = count
            return
        
        count = CpuHelper().get_limit()
        if count > 0:
            self.process_count = count
            return
        
        self.process_count = FALLBACK_PROCESS_COUNT

    def set_global_exclusion_paths(self, paths: List[str]) -> None:
        for path in paths:
            if not path_exists(path):
                raise FileNotFoundException(f'global_exclusion_path does not exist ({path})')
            self.global_exclusion_paths.append(path)

        self.global_exclusion_paths = list(set(self.global_exclusion_paths))

    def add_ruleset(self, type: Type, paths: List[str] = []) -> None:
        self._validate_paths(paths)
        self.rulesets[type] = [get_abspath(path) for path in paths]

    def _validate_paths(self, paths: List[str]) -> None:
        if paths is None:
            return

        for path in paths:
            if path_exists(path):
                continue
            raise FileNotFoundException(f'File {path} does not exist')

        return


config = Config()