from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict

from deepsecrets.core.utils.lifecycle_hooks import FileLifecycleHooks
from deepsecrets.core.utils.log import logger
from deepsecrets.core.engines.iengine import IEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.itokenizer import Tokenizer
from deepsecrets.core.utils.progress import FileProgress


class EngineWithTokenizer(BaseModel):
    engine: IEngine
    tokenizer: Tokenizer

    model_config = ConfigDict(arbitrary_types_allowed=True)


class FileAnalyzer:
    file: File
    engine_tokenizers: List[EngineWithTokenizer]
    tokens: Dict[Tokenizer, List[Token]]
    progress: FileProgress
    task_reporter: Any
    task_id: Optional[int]

    def __init__(self, file: File):
        self.engine_tokenizers = []
        self.file = file
        self.tokens = {}
        self.progress = FileProgress(tokenizers_total=len(self.engine_tokenizers))
        self.lifecycle = FileLifecycleHooks(reporter=None, task_id=None, progress=self.progress)
        self.task_reporter = None
        self.task_id = None
        self.progress.set_file_size(self.file.length)

    def attach_global_task_reporter(self, task_reporter, task_id):
        self.task_reporter = task_reporter
        self.task_id = task_id
        self.lifecycle.task_id = self.task_id
        self.lifecycle.reporter = self.task_reporter

    def add_engine(self, engine: IEngine, tokenizers: List[Tokenizer]) -> None:
        for tokenizer in tokenizers:
            self.engine_tokenizers.append(EngineWithTokenizer(engine=engine, tokenizer=tokenizer))
            self.progress.tokenizers_total += 1

    def process(self) -> List[Finding]:
        results: List[Finding] = []
        self.lifecycle.on_start()
        try:
            for et in self.engine_tokenizers:
                results.extend(self._run_engine(et))
        except Exception:
            pass

        self.lifecycle.on_finish()
        return results

    def _run_engine(self, et: EngineWithTokenizer) -> List[Finding]:
        results: List[Finding] = []
        processed_values: Dict[int, bool] = {}

        if et.tokenizer not in self.tokens:
            self.tokens[et.tokenizer] = et.tokenizer.tokenize(self.file)
            self.progress.on_tokenization_finished(token_count=len(self.tokens[et.tokenizer]))

        tokens: List[Token] = self.tokens[et.tokenizer]

        for token in tokens:
            self.lifecycle.on_token_processing_start(token)

            is_known_content = processed_values.get(token.val_hash())
            if is_known_content is not None and is_known_content is False:
                continue

            processed_values[token.val_hash()] = False

            try:
                findings: List[Finding] = et.engine.search(token)
                for finding in findings:
                    finding.map_on_file(file=self.file, relative_start=token.span[0])
                    results.append(finding)
                    processed_values[token.val_hash()] = True

                self.lifecycle.on_token_processing_end(len(findings))

            except Exception as e:
                logger.exception('Unable to process token', extra={'info': e})
                continue

        return results
