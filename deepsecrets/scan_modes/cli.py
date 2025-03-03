import logging
import os
from typing import Any, Dict, List, Type, Optional

from dotwiz import DotWiz

from deepsecrets import PROFILER_ON, console
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.modes.iscan_mode import ScanMode
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.utils.log import logger
from deepsecrets.core.utils.file_analyzer import FileAnalyzer


class CliScanMode(ScanMode):

    def prepare_for_scan(self) -> None:
        self.engines_enabled: Dict[Type, bool] = {}
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

    def analyzer_bundle(self) -> DotWiz:
        bundle = super().analyzer_bundle()
        bundle.update(
            workdir=self.config.workdir_path,
            engines=self.engines_enabled,
            rulesets=self.rulesets,
        )
        return bundle

    @staticmethod
    def _per_file_analyzer(bundle: Any, file: Any, task_id: Optional[int] = None, task_reporter: Optional[Any] = None) -> List[Finding]:  # type: ignore
        if logger.level == logging.DEBUG:
            pass

        results: List[Finding] = []

        if not isinstance(file, str):
            raise Exception('Filepath as str expected')

        file = File(path=file, relative_path=file.replace(f'{bundle.workdir}/', ''))
        if file.length == 0:
            return results

        file_analyzer = FileAnalyzer(file)
        file_analyzer.attach_global_task_reporter(task_reporter=task_reporter, task_id=task_id)

        fct = FullContentTokenizer()
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
                    ruleset=bundle.ruleset.get(HashedSecretsRulesetBuilder.ruleset_name, [])
                )
                file_analyzer.add_engine(hashed_secret_engine, [lex])

            if eng == SemanticEngine.name:
                semantic_engine = SemanticEngine(regex_engine)
                file_analyzer.add_engine(semantic_engine, [lex])

        try:
            results = file_analyzer.process(threaded=False)
        except Exception as e:
            logger.exception(e)

        if PROFILER_ON:
            pass

        return results
