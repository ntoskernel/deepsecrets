from multiprocessing import RLock
from multiprocessing.pool import Pool
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel, ConfigDict

from deepsecrets.core.utils.log import logger
from deepsecrets.core.engines.iengine import IEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.itokenizer import Tokenizer


class EngineWithTokenizer(BaseModel):
    engine: IEngine
    tokenizer: Tokenizer

    model_config = ConfigDict(arbitrary_types_allowed = True)


class Progress:
    started: bool
    finished: bool
    total_tokens: int
    processed_count: int

    findings: int

    def __init__(self):
        self.started = False
        self.finished = False
        self.total_tokens = 0
        self.processed_count = 0
        self.findings = 0

    def on_tokenization_finished(self, token_count: int):
        self.total_tokens += token_count

    def on_token_processing_start(self):
        self.started = True
        self.processed_count += 1
            
    def on_finish(self):
        self.started = False
        self.finished = True
    
    def add_findings_count(self, count: int):
        self.findings += count

    def report(self):
        return {
            'started': self.started,
            'finished': self.finished,
            'total_tokens': self.total_tokens,
            'processed': self.processed_count,
            'findings': self.findings,
        }


class FileAnalyzer:
    file: File
    engine_tokenizers: List[EngineWithTokenizer]
    tokens: Dict[Type, List[Token]]
    pool_class: Type
    progress: Progress
    task_reporter: Any
    task_id: str

    def __init__(self, file: File, pool_class: Optional[Type] = None):
        if pool_class is not None:
            self.pool_class = Pool
        else:
            self.pool_class = pool_class

        self.engine_tokenizers = []
        self.file = file
        self.tokens = {}
        self.tokenizers_lock = RLock()
        self.progress = Progress()
        self.task_reporter = None
        self.task_id = None

    def attach_global_task_reporter(self, task_reporter, task_id):
        self.task_reporter = task_reporter
        self.task_id = task_id
        self.global_report()
    
    def global_report(self):
        if self.task_reporter is None:
            return
        
        self.task_reporter[self.task_id] = self.progress.report()

    def add_engine(self, engine: IEngine, tokenizers: List[Tokenizer]) -> None:
        for tokenizer in tokenizers:
            self.engine_tokenizers.append(EngineWithTokenizer(engine=engine, tokenizer=tokenizer))

    def process(self, threaded: bool = False) -> List[Finding]:
        results: List[Finding] = []

        if threaded:  # pragma: nocover
            with self.pool_class(2) as pool:
                engine_results = pool.imap(self._run_engine, self.engine_tokenizers)
                pool.close()
                pool.join()

            if engine_results is None:
                return results

            for er in engine_results:
                if not er:
                    continue
                results.extend(er)

        else:
            for et in self.engine_tokenizers:
                results.extend(self._run_engine(et))

        return results

    def _run_engine(self, et: EngineWithTokenizer) -> List[Finding]:
        results: List[Finding] = []
        processed_values: Dict[int, bool] = {}

        with self.tokenizers_lock:
            if et.tokenizer not in self.tokens:
                self.tokens[et.tokenizer] = et.tokenizer.tokenize(self.file)
                self.progress.on_tokenization_finished(len(self.tokens[et.tokenizer]))

        tokens: List[Token] = self.tokens[et.tokenizer]

        for token in tokens:
            self.on_token_processing_start(token)

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
                
                self.on_token_processing_end(len(findings))

            except Exception as e:
                logger.exception('Unable to process token')
                continue
        
        self.progress.on_finish()
        return results
    
    def on_token_processing_start(self, token: Token):
        self.progress.on_token_processing_start()
        self.global_report()

    def on_token_processing_end(self, findings_count: int):
        self.progress.add_findings_count(findings_count)
        self.global_report()