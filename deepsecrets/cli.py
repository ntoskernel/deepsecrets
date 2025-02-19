import argparse
from datetime import datetime
import json
import logging
import sys
from argparse import RawTextHelpFormatter
from typing import List
from jschema_to_python.to_json import to_json

from deepsecrets import MODULE_NAME, console
from deepsecrets.config import Config, config, Output
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.finding import Finding, FindingResponse
from deepsecrets.core.rulesets.false_findings import FalseFindingsBuilder
from deepsecrets.core.rulesets.hashed_secrets import (
    HashedSecretsRulesetBuilder
)
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.utils.fs import get_abspath, get_path_inside_package
from deepsecrets.core.utils.log import logger, build_logger
from deepsecrets.scan_modes.cli import CliScanMode

from rich.progress import (
    SpinnerColumn,
    Progress,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich import box
from rich.text import Text
from rich.align import Align


DISABLED = 'disabled'
FINDINGS_DETECTED_RETURN_CODE = 66

progress_bar = Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    TextColumn("[bold red]{task.fields[findings]}", justify="left"),
    BarColumn(bar_width=None),
    TaskProgressColumn(),
    TimeRemainingColumn(),
    console=console,
    refresh_per_second=10,
    expand=True,
)

class DeepSecretsCliTool:
    argparser: argparse.ArgumentParser

    def __init__(self, args: List[str]):
        self.args = args
        self._build_argparser()

    def say_hello(self) -> None:
        console.line(2)
        console.rule('DeepSecrets', characters='=')

        from rich.panel import Panel
        console.print(
            Align(
                Panel.fit(
                    Text('____________________________________', style='reverse'),
                    padding=(0,0),
                    title=f'A better tool for Secret Scanning ',
                    subtitle='version 1.4.0',
                ),
                align='center'
            )
        )
        console.line(2)



    def _build_argparser(self) -> None:
        parser = argparse.ArgumentParser(
            prog=MODULE_NAME,
            description='DeepSecrets - a better tool for secrets search',
            formatter_class=RawTextHelpFormatter,
        )

        parser.add_argument(
            '--target-dir',
            required=True,
            type=str,
            help="Path to the directory with code you'd like to analyze",
        )

        parser.add_argument(
            '--regex-rules',
            nargs='*',
            type=str,
            help='Paths to your Regex Rulesets.\n'
            "- Set 'disable' to turn off regex checks\n"
            '- Ignore this argument to use the built-in ruleset.\n'
            "- Using your own rulesets disables the default one. Add 'built-in' to the args list to enable it\n"
            'eq. --regex-rules built-in /root/my_regex_rules.json\n',
            default=['built-in'],
        )

        parser.add_argument(
            '--hashed-values',
            nargs='*',
            type=str,
            help='Path to your Hashed Values set.\n' "Don't set any value to disable this checks\n",
        )

        parser.add_argument(
            '--semantic-analysis',
            nargs='*',
            type=str,
            help='Controls semantic checks (enabled by default)\n'
            "- Set 'disable' to turn off semantic checks (not recommended)\n"
            'eq. --semantic-analysis disable',
            default=['built-in'],
        )

        parser.add_argument(
            '--excluded-paths',
            nargs='*',
            type=str,
            help='Paths to your Excluded Paths file.\n'
            "- Set 'disable' to scan everything (may affect performance)\n"
            '- Ignore this argument to use the built-in ruleset.\n'
            "- Using your own rulesets disables the default one. Add 'built-in' to the args list to enable it\n"
            'eq. --excluded-paths built-in /root/my_excluded_paths.json\n',
            default=['built-in'],
        )

        parser.add_argument(
            '--false-findings',
            nargs='*',
            type=str,
            help='Paths to your False Findings file.\n'
            'Use to filter findings you sure are false positives\n'
            'File syntax is the same as in regex rules\n'
            'eq. --false-findings /root/my_false_findings.json\n',
        )

        parser.add_argument(
            '-v',
            '--verbose',
            action='store_true',
            help='Verbose mode',
        )

        parser.add_argument(
            '--reflect-findings-in-return-code',
            action='store_true',
            help='Return code of 66 if any findings are detected during scan',
        )

        parser.add_argument(
            '--process-count',
            type=int,
            default=0,
            help='Number of processes in a pool for file analysis (one process per file)\n'
            'Default: number of processor cores of your machine or cpu limit of your container from cgroup.\n'
            'If all checks are failed the fallback value is 4'
        )

        parser.add_argument(
            '--max-file-size',
            type=int,
            default=0,
            help='Maximum size of a file (in bytes) the tool should analyze,\n'
            'files with exceeding size will be ingored.\n'
            'Big files (more than 5M) may contain useless blobs and cause performance degradation\n'
            'Default: 0, which means "no limit".\n'
        )

        parser.add_argument(
            '--multiprocessing-context',
            type=str,
            default='spawn',
            choices=['fork', 'spawn', 'forkserver'],
            help='Experimental: control the multiprocessing context\n'
        )

        parser.add_argument('--outfile', required=True, type=str)
        parser.add_argument(
            '--outformat',
            default='json',
            type=str,
            choices=['json', 'dojo-sarif'],
            help='"json": internal format (default)\n'
                '"dojo-sarif": SARIF format compatible with DefectDojo\n'
            )

        parser.add_argument(
            '--disable-masking',
            action='store_true',
            help='Secrets are rendered masked inside reports by default.\n'
            'Use this flag if you want to render found secrets in plaintext.',
        )

        self.argparser = parser

    def parse_arguments(self) -> None:
        logger = build_logger()

        user_args = self.argparser.parse_args(args=self.args[1:])
        if user_args.verbose:
            config.set_logging_level(logging.DEBUG)
            logger = build_logger(config.logging_level)  # flake8: noqa

        if user_args.disable_masking:
            config.set_disable_masking(True)

        self.say_hello()

        config.set_workdir(user_args.target_dir)
        config.set_max_file_size(user_args.max_file_size)
        config.set_process_count(user_args.process_count)
        config.set_mp_context(user_args.multiprocessing_context)
        config.output = Output(type=user_args.outformat, path=user_args.outfile)

        if user_args.reflect_findings_in_return_code:
            config.return_code_if_findings = True

        EXCLUDE_PATHS_BUILTIN = get_path_inside_package('rules/excluded_paths.json')
        if user_args.excluded_paths is not None:
            rules = [rule.replace('built-in', EXCLUDE_PATHS_BUILTIN) for rule in user_args.excluded_paths]
            config.set_global_exclusion_paths(rules)

        config.engines = []

        REGEX_BUILTIN_RULESET = get_path_inside_package('rules/regexes.json')
        if user_args.regex_rules is not None:
            rules = [rule.replace('built-in', REGEX_BUILTIN_RULESET) for rule in user_args.regex_rules]
            config.engines.append(RegexEngine)
            config.add_ruleset(RegexRulesetBuilder, rules)

        conf_semantic_analysis = user_args.semantic_analysis
        if conf_semantic_analysis is not None and conf_semantic_analysis != DISABLED:
            config.engines.append(SemanticEngine)

        conf_hashed_ruleset = user_args.hashed_values
        if conf_hashed_ruleset is not None and conf_hashed_ruleset != DISABLED:
            config.engines.append(RegexEngine)
            config.add_ruleset(HashedSecretsRulesetBuilder, conf_hashed_ruleset)

        conf_false_findings_ruleset = user_args.false_findings
        if conf_false_findings_ruleset is not None:
            config.add_ruleset(FalseFindingsBuilder, conf_false_findings_ruleset)

    def get_current_config(self) -> Config:
        return config
    

    def start(self) -> None:  # pragma: nocover
        startup_time = datetime.now()
        try:
            self.parse_arguments()
        except Exception as e:
            logger.exception(e)
            sys.exit(1)
        
        console.rule(f'Planning a scan against {config.workdir_path} using {config.process_count} process(es)', characters='=')
        console.line()
        if config.disable_masking is True:
            console.print(f'[bold red]:warning: SECRETS MASKING IS DISABLED. REPORT WILL CONTAIN SECRETS IN PLAINTEXT. BE CAREFUL!\n', justify='center')

        if config.return_code_if_findings is True:
            console.print(f'[bold yellow]:warning:[/bold yellow] The tool will return code of {FINDINGS_DETECTED_RETURN_CODE} if any findings are detected\n')
        
        mode = CliScanMode(config=config)

        console.line()
        console.rule(f'Starting analysis', characters='—')
        console.line()
        mode.set_progress_bar(progress_bar)

        progress_bar.start()
        findings: List[Finding] = mode.run()
        progress_bar.stop()
        finish_time = datetime.now()

        report_path = get_abspath(config.output.path)

        console.line()
        console.print('[bold green]Scanning finished successfully', justify='center')
        console.line()

        console.rule('REPORT', characters='=')
        console.line()
        table = Table(box=box.HORIZONTALS, show_header=False, row_styles=['blink'], style='dim', width=80)
        table.add_column()
        table.add_column(justify='right')
        table.add_row(Align('Files (Tokens) Processed', vertical='middle'), f'{str(len(mode.filepaths))} ({mode.get_total_tokens_processed()})')
        table.add_row(Align('Elapsed', vertical='middle'), f'{(finish_time-startup_time).total_seconds():.1f}s')
        findings_line_color = '[bold red]' if len(findings) > 0 else '[bold green]'
        table.add_row(Align(f'{findings_line_color}Potential Findings', vertical='middle'), f'{findings_line_color}{str(len(findings))}')
        table.add_row(Align('Report Location', vertical='middle'), report_path)
        console.print(Align(table, align='center'))

        with open(report_path, 'w+') as f:

            if config.output.type == 'json':
                json.dump(FindingResponse.from_list(findings, config.disable_masking), f)
            
            if config.output.type == 'dojo-sarif':
                f.write(to_json(FindingResponse.dojo_sarif_from_list(findings, config.disable_masking)))

        if len(findings) > 0 and config.disable_masking:
            console.print('[bold red]:warning: SECRETS MASKING WAS DISABLED, THE REPORT CONTAINS POTENTIAL SECRETS IN PLAINTEXT.\nBE CAREFUL!', justify='center')
        
        console.line()
        console.print(Align('[italic]Any missed secret or massive false positive rate is potentially a bug', align='center'))
        console.print(Align('[italic]So feel free to report bugs and difficulties here', align='center'))
        console.print(Align('[italic]https://github.com/ntoskernel/deepsecrets/issues', align='center'))
        console.line()
        console.print(Align('[bold green]FINISHED', align='center'))
        console.line(2)

        if len(findings) > 0 and config.return_code_if_findings:
            sys.exit(FINDINGS_DETECTED_RETURN_CODE)