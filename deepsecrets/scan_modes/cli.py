import logging
import os
from dataclasses import replace
from typing import Any, Dict, Optional

from deepsecrets import PROFILER_ON, console
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.modes.iscan_mode import ScanMode
from deepsecrets.core.model.internal.processing import AnalyzerBundle, PerFileAnalysisResult
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.rulesets.variable_scoring import VariableScoringRulesetBuilder
from deepsecrets.core.tokenizers.cheap_var_search import CheapVarSearchTokenizer
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.utils.lifecycle_hooks import JobLifecycleHooks
from deepsecrets.core.utils.log import get_error_list, logger
from deepsecrets.core.utils.file_analyzer import FileAnalyzer
from deepsecrets.core.utils.fs import get_relative_path
from deepsecrets.core.utils.progress import Progress


class CliScanMode(ScanMode):

    def prepare_for_scan(self) -> None:
        self.engines_enabled: Dict[str, bool] = {}
        self.rulesets = {}

        console.line()
        console.print(f'[*] Found [bold green]{len(self.filepaths)} applicable files[/bold green] for the scan')
        if len(self.filepaths) == 0:
            return

        for engine in self.config.engines:
            self.engines_enabled[engine.name] = True

        for ruleset_builder, paths in self.config.rulesets.items():
            builder = ruleset_builder()
            for path in paths:
                builder.with_rules_from_file(os.path.abspath(path))
            self.rulesets[builder.ruleset_name] = builder.rules

    def analyzer_bundle(self) -> AnalyzerBundle:
        return replace(super().analyzer_bundle(), engines=self.engines_enabled, rulesets=self.rulesets)

    @staticmethod
    def _per_file_analyzer(bundle: AnalyzerBundle, file: Any, task_id: Optional[int] = None, task_reporter: Optional[Any] = None) -> PerFileAnalysisResult:  # type: ignore

        def __finalize(result: PerFileAnalysisResult):
            if bundle.benchmarking_mode is True:
                result._file = file

            result.processing_time_seconds = int((lifecycle.end_ts - lifecycle.start_ts).total_seconds())
            result.errors = get_error_list()
            return result

        progress = Progress()
        lifecycle = JobLifecycleHooks(
            task_id=task_id,
            progress=progress,
            reporter=task_reporter,
        )

        lifecycle.on_start()
        if logger.level == logging.DEBUG:
            pass

        result = PerFileAnalysisResult(findings=[], errors=[], internal_task_id=task_id)

        if not isinstance(file, str):
            raise Exception('Filepath as str expected')

        try:
            file = File(path=file, relative_path=get_relative_path(file, bundle.workdir))
        except Exception as e:
            logger.error(f'Unable to open the file: {e}')
            lifecycle.on_failure(task_reporter[task_id])
            return __finalize(result)

        if file.length == 0:
            lifecycle.on_finish(task_reporter[task_id])
            return __finalize(result)

        file_analyzer = FileAnalyzer(file)
        file_analyzer.attach_global_task_reporter(task_reporter=task_reporter, task_id=task_id)

        fct = FullContentTokenizer()
        cheap_var_search = CheapVarSearchTokenizer()
        lex = LexerTokenizer(deep_token_inspection=True)

        regex_engine = RegexEngine(
            ruleset=bundle.rulesets.get(RegexRulesetBuilder.ruleset_name, []),
        )

        for eng, enabled in bundle.engines.items():
            if not enabled:
                continue

            if eng == RegexEngine.name:
                file_analyzer.add_engine(regex_engine, [fct])

            if eng == HashedSecretEngine.name:
                hashed_secret_engine = HashedSecretEngine(
                    ruleset=bundle.rulesets.get(HashedSecretsRulesetBuilder.ruleset_name, [])
                )
                file_analyzer.add_engine(hashed_secret_engine, [lex])

            if eng == SemanticEngine.name:
                semantic_engine = SemanticEngine(
                    regex_engine, ruleset=bundle.rulesets.get(VariableScoringRulesetBuilder.ruleset_name, [])
                )
                file_analyzer.add_engine(semantic_engine, [lex, cheap_var_search])

        try:
            result.findings = file_analyzer.process()
        except Exception as e:
            logger.exception(e)

        if PROFILER_ON:
            pass

        if task_reporter is not None:
            lifecycle.on_finish(task_reporter.get('task_id'))

        return __finalize(result)
