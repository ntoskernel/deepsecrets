import argparse
from datetime import datetime
import os
from argparse import RawTextHelpFormatter
from typing import Dict, List
from jschema_to_python.to_json import to_json
from multiprocessing import get_all_start_methods

from deepsecrets import MODULE_NAME, console
from deepsecrets.config import (
    CONFIDENCE_LEVELS,
    CONFIDENCE_RANGE,
    DEFAULT_CONFIDENCE_LEVEL,
    DEFAULT_DEEP_MAX_SIZE,
    SCANNER_VERSION,
    TIER_FLOORS,
    Config,
    Output,
)
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.helpers.finding_tags import PUBLISHABLE, TAGS, TEST_CONTEXT, WEAK_PASSWORD
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.response.dojo_sarif import DojoSarifResponseBuilder
from deepsecrets.core.rulesets.false_findings import FalseFindingsBuilder
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.rulesets.regex_candidate_scoring import RegexCandidateScoringRulesetBuilder
from deepsecrets.core.rulesets.variable_scoring import VariableScoringRulesetBuilder
from deepsecrets.core.ui.progress_bar import DSApplicationProgess
from deepsecrets.core.ui.time_remaining_column import SyncedTimeRemainingColumn
from deepsecrets.core.utils.exceptions import FileNotFoundException
from deepsecrets.core.utils.fs import get_abspath, get_path_inside_package
from deepsecrets.core.utils.log import logger
from deepsecrets.scan_modes.cli import CliScanMode
from deepsecrets.core.modes.iscan_mode import WorkerStartupError
from deepsecrets.core.utils.environment import is_ci_environment
from deepsecrets.core.utils.multiprocessing_setup import TempDirTooLongError, default_start_method, stop_forkserver

from rich.progress import SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table, Column
from rich import box
from rich.text import Text
from rich.align import Align


def with_built_in(paths: List[str], shipped: str) -> List[str]:
    """A ruleset flag's paths, with 'built-in' standing for the file shipped at `shipped` inside the package."""
    built_in = get_path_inside_package(shipped)
    return [path.replace('built-in', built_in) for path in paths]


class ReturnCodes:
    OK = 0
    ERROR = 1
    FINDINGS_DETECTED = 66


overall_time_column = SyncedTimeRemainingColumn()
progress_bar = DSApplicationProgess(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}", table_column=Column(max_width=60, no_wrap=True)),
    TextColumn("[bold blue]{task.fields[size]}"),
    BarColumn(bar_width=None),
    TaskProgressColumn('[progress.percentage]{task.percentage:>3.1f}%'),
    overall_time_column,
    TextColumn("[bold red]{task.fields[findings]}", justify="right"),
    TextColumn("[bold red]{task.fields[errors]}", justify="right"),
    console=console,
    refresh_per_second=5,
    expand=True,
    speed_estimate_period=90,
)
overall_time_column.progress_instance = progress_bar


class DeepSecretsCliTool:
    argparser: argparse.ArgumentParser
    # built by parse_arguments, one per parse
    config: Config

    def __init__(self, args: List[str]):
        self.args = args
        self._build_argparser()

    def say_hello(self) -> None:
        console.line(2)
        console.rule('DeepSecrets', characters='=')
        console.print(
            Align(
                Panel.fit(
                    Text('____________________________________', style='reverse'),
                    padding=(0, 0),
                    title='A better tool for Secret Scanning ',
                    subtitle=f'version {SCANNER_VERSION}',
                ),
                align='center',
            )
        )
        console.line(2)

    def _build_argparser(self) -> None:
        """The command line. Every ruleset flag takes a list of files, where 'built-in' stands for the shipped one."""
        parser = argparse.ArgumentParser(
            prog=MODULE_NAME,
            description='DeepSecrets - a better tool for secrets search',
            formatter_class=RawTextHelpFormatter,
        )

        def ruleset_help(purpose: str, flag: str, example: str, *extra: str) -> str:
            lines = [
                purpose,
                *extra,
                '- Leave the flag out to use the built-in ruleset.',
                "- Your own files replace the built-in ruleset; list 'built-in' among them to add it back",
                f'e.g. {flag} built-in /root/{example}.json',
            ]
            return '\n'.join(lines) + '\n'

        parser.add_argument(
            '--target-dir',
            required=True,
            type=str,
            help='The directory to scan',
        )
        parser.add_argument(
            '--regex-rules',
            nargs='*',
            type=str,
            default=['built-in'],
            help=ruleset_help(
                'Regex rulesets to match.',
                '--regex-rules',
                'my_regex_rules',
                "- Set 'disable' to turn the regex checks off",
            ),
        )
        parser.add_argument(
            '--regex-candidate-scoring-rules',
            nargs='*',
            type=str,
            default=['built-in'],
            help=ruleset_help(
                'Rules that judge a regex match (a candidate) before it is reported: placeholders, values that\n'
                'read as language, hosts, test paths. They judge the matches of regex rules with an "evidence" class.',
                '--regex-candidate-scoring-rules',
                'my_candidate_rules',
            )
            + '- Give the flag no value to report regex matches unjudged, as before 2.2\n',
        )
        parser.add_argument(
            '--hashed-values',
            nargs='*',
            type=str,
            help='A set of hashed values to look for.\nThe check is off when the flag is left out or has no value\n',
        )
        parser.add_argument(
            '--semantic-analysis',
            nargs='*',
            type=str,
            default=['built-in'],
            help='Semantic checks: variables judged by their names and values (on by default).\n'
            "- Set 'disable' to turn them off (not recommended)\n"
            'e.g. --semantic-analysis disable\n'
            'The rules come from --variable-scoring-rules',
        )
        parser.add_argument(
            '--variable-scoring-rules',
            nargs='*',
            type=str,
            default=['built-in'],
            help=ruleset_help(
                'Rules that judge whether a variable holds a secret, by its name, its value and its file path.',
                '--variable-scoring-rules',
                'my_var_scoring_rules',
            ),
        )
        parser.add_argument(
            '--excluded-paths',
            nargs='*',
            type=str,
            default=['built-in'],
            help=ruleset_help(
                'Files of path patterns to skip.',
                '--excluded-paths',
                'my_excluded_paths',
                "- Set 'disable' to scan everything (slower)",
            ),
        )
        parser.add_argument(
            '--skip-bundles',
            action='store_true',
            help='Also skip minified JavaScript, source maps and bundles (*.min.js, *.map, *.bundle.js), whatever\n'
            "--excluded-paths lists (except 'disable'). Most of them are larger than --deep-max-size and get the\n"
            'fast analysis anyway.\n',
        )
        parser.add_argument(
            '--deep-max-size',
            type=int,
            default=DEFAULT_DEEP_MAX_SIZE,
            help='Files larger than this many bytes get the fast analysis: the regex rules and the variable search,\n'
            'without the language lexer, which costs most of the scan time on big files and rarely finds more there.\n'
            f'Default: {DEFAULT_DEEP_MAX_SIZE}. 0 gives every file the full analysis.\n',
        )
        floors = TIER_FLOORS
        # one cut or the other: a named level, or a number
        cut = parser.add_mutually_exclusive_group()
        cut.add_argument(
            '--confidence-level',
            type=str,
            default=DEFAULT_CONFIDENCE_LEVEL,
            choices=list(CONFIDENCE_LEVELS),
            help=f'The lowest confidence to report, from all to very-high (default: {DEFAULT_CONFIDENCE_LEVEL}).\n'
            f'"low" reports every finding; "medium", "high" and "very-high" keep confidence {floors["medium"]}, '
            f'{floors["high"]} and {floors["very-high"]} or more,\n'
            'the findings of the SARIF tiers of the same names and above.\n'
            '"all" also reports the regex matches the scanner judged not to be secrets (placeholders, examples),\n'
            'at confidence 0 with an -INFO rule id.\n',
        )
        cut.add_argument(
            '--min-confidence',
            type=int,
            default=None,
            choices=CONFIDENCE_RANGE,
            metavar='N',
            help='Report findings of confidence N or more, '
            f'N from {CONFIDENCE_RANGE[0]} to {CONFIDENCE_RANGE[-1]}: any cut, where --confidence-level\n'
            'offers the floors of the tiers. Like every level but "all", it leaves out the regex matches the\n'
            'scanner judged not to be secrets. Not together with --confidence-level.\n',
        )
        parser.add_argument(
            '--exclude-tags',
            nargs='+',
            choices=TAGS,
            metavar='TAG',
            help='Leave out the findings that carry any of these tags. A tag says what sort of secret a finding is:\n'
            f'"{WEAK_PASSWORD}": a weak value under a password-like name (S106);\n'
            f'"{PUBLISHABLE}": a key made to ship to clients (a site key, a Stripe pk_ key, a Mapbox pk. token);\n'
            f'"{TEST_CONTEXT}": in a test, spec, fixture, mock, example or sample path, relative to --target-dir.\n'
            'The SARIF report carries the tags of each result in its "tags" property.\n'
            f'e.g. --exclude-tags {TEST_CONTEXT} {PUBLISHABLE}\n',
        )
        parser.add_argument(
            '--false-findings',
            nargs='*',
            type=str,
            help='Files of patterns for findings you know are false positives: a finding whose value matches\n'
            'one is dropped. The syntax is that of the regex rules\n'
            'e.g. --false-findings /root/my_false_findings.json\n',
        )
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
        parser.add_argument(
            '--reflect-findings-in-return-code',
            action='store_true',
            help='Exit with code 66 when the scan reports any finding',
        )
        parser.add_argument(
            '--process-count',
            type=int,
            default=0,
            help='How many worker processes analyse files, one file each at a time.\n'
            "Default: the machine's processor count, or the CPU limit of the container (cgroup);\n"
            '4 when neither can be read',
        )
        parser.add_argument(
            '--max-file-size',
            type=int,
            default=0,
            help='Skip files larger than this many bytes.\n'
            'Very big files (over 5 MB) are mostly blobs and slow the scan down.\n'
            'Default: 0, no limit.\n',
        )
        parser.add_argument(
            '--multiprocessing-context',
            type=str,
            default=None,
            # the platform's own: fork and forkserver do not exist on Windows
            choices=get_all_start_methods(),
            help='How worker processes start. Default: forkserver where available (Linux, macOS), spawn elsewhere.\n'
            'forkserver workers share the scanner already loaded in the server instead of loading it again.\n',
        )
        parser.add_argument(
            '--ci',
            action=argparse.BooleanOptionalAction,
            default=None,
            help='CI mode: no live progress bars, a plain progress line every 30 s, and no progress manager process.\n'
            'Default: on inside a CI service (CI, GITHUB_ACTIONS, GITLAB_CI and similar variables) or when the\n'
            'output is not a terminal; --no-ci forces the live display.\n',
        )
        parser.add_argument('--outfile', required=True, type=str, help='Where to write the report')
        parser.add_argument(
            '--outformat',
            default='sarif',
            type=str,
            choices=['json', 'sarif', 'dojo-sarif'],
            help='"sarif": SARIF format (specification accurate, default)\n'
            '"dojo-sarif": SARIF format (compatible with DefectDojo\'s parser)\n'
            '"json": the old internal format, removed in 2.2.0 (exits with an error)',
        )
        parser.add_argument(
            '--disable-masking',
            action='store_true',
            help='Write the secrets found into the report in plain text. They are masked by default;\n'
            'be extremely careful with a report written with this flag.',
        )
        parser.add_argument(
            '--report-diagnostics',
            action='store_true',
            help='Add scan diagnostics to a SARIF report: every file found under the target directory in\n'
            'run.artifacts (scan time in ms, status, skip reason, analysis depth) and per-file errors in\n'
            'run.invocations.\n',
        )
        # for in-process callers and the benchmark harness
        parser.add_argument('--benchmarking-mode', help=argparse.SUPPRESS, action='store_true')
        parser.add_argument('--oneshot', help=argparse.SUPPRESS, type=str, default=None)

        self.argparser = parser

    def parse_arguments(self) -> None:
        """Builds a fresh Config from the arguments, so nothing an earlier parse set carries over (KI-CLI-12). Paths
        are checked here, before any scan starts."""
        config = self.config = Config()
        args = self.argparser.parse_args(args=self.args[1:])

        config.set_disable_masking(args.disable_masking)
        config.set_report_diagnostics(args.report_diagnostics)
        config.set_confidence_level(args.confidence_level)
        config.set_min_confidence(args.min_confidence)
        config.set_excluded_tags(args.exclude_tags)
        config._set_benchmarking_mode(args.benchmarking_mode)
        config.return_code_if_findings = args.reflect_findings_in_return_code

        self.say_hello()

        config.set_workdir(args.target_dir)
        config.set_oneshot_path(args.oneshot)
        config.set_max_file_size(args.max_file_size)
        config.set_deep_max_size(args.deep_max_size)
        config.set_process_count(args.process_count)
        config.set_mp_context(args.multiprocessing_context or default_start_method())
        config.set_ci_mode(is_ci_environment() if args.ci is None else args.ci)
        config.set_verbose(args.verbose)
        config.output = Output(type=args.outformat, path=args.outfile)
        # checked now, not when the report is written after the whole scan
        report_dir = os.path.dirname(get_abspath(args.outfile))
        if not os.path.isdir(report_dir):
            raise FileNotFoundException(f'--outfile: the directory {report_dir} does not exist')

        self._add_engines_and_rulesets(config, args)

    @staticmethod
    def _add_engines_and_rulesets(config: Config, args: argparse.Namespace) -> None:
        """The engines the flags turn on, and the rule files each ruleset reads."""
        if args.excluded_paths is not None:
            paths = with_built_in(args.excluded_paths, 'rules/excluded_paths.json')
            if args.skip_bundles and 'disable' not in args.excluded_paths:
                paths.append(get_path_inside_package('rules/excluded_bundles.json'))
            config.set_global_exclusion_paths(paths)

        if args.regex_rules is not None:
            config.engines.append(RegexEngine)
            config.add_ruleset(RegexRulesetBuilder, with_built_in(args.regex_rules, 'rules/regexes.json'))
            if args.regex_candidate_scoring_rules is not None:
                rules = with_built_in(args.regex_candidate_scoring_rules, 'rules/regex_candidate_scoring_rules.json')
                config.add_ruleset(RegexCandidateScoringRulesetBuilder, rules)

        # the help's 'disable' is not honoured: the engine is on whatever the flag lists (KI-CLI-02)
        if args.semantic_analysis is not None:
            config.engines.append(SemanticEngine)
            if args.variable_scoring_rules is not None:
                rules = with_built_in(args.variable_scoring_rules, 'rules/variable_scoring_rules.json')
                config.add_ruleset(VariableScoringRulesetBuilder, rules)

        # the flag without a value disables the check, as its help says; an empty ruleset would only keep the lexer on
        # every file for nothing (the hashed engine lexes files over --deep-max-size too)
        if args.hashed_values:
            config.engines.append(HashedSecretEngine)
            config.add_ruleset(HashedSecretsRulesetBuilder, args.hashed_values)

        if args.false_findings is not None:
            config.add_ruleset(FalseFindingsBuilder, args.false_findings)

    def get_current_config(self) -> Config:
        return self.config

    def start(self) -> int:  # pragma: nocover
        startup_time = datetime.now()
        try:
            self.parse_arguments()
        except Exception as e:
            logger.exception(e)
            return ReturnCodes.ERROR
        config = self.config

        if config.output.type == 'json':
            self._refuse_json_output()
            return ReturnCodes.ERROR

        self._print_plan()

        try:
            mode = CliScanMode(config=config)
        except TempDirTooLongError as e:
            console.print(f'[bold red][!] Cannot start worker processes: {e}.[/bold red]')
            return ReturnCodes.ERROR

        console.line()

        if not config.ci_mode:
            # run() starts it once the worker pool exists
            mode.set_progress_bar(progress_bar)
            mode.progress_bar.set_start_time(startup_time)

        try:
            findings, errors, timings = mode.run()
        except WorkerStartupError as e:
            if mode.progress_bar is not None:
                mode.progress_bar.stop()
            console.print(f'[bold red][!] Scan stopped: {e}. Every file it took would fail the same way.[/bold red]')
            self._release(mode)
            return ReturnCodes.ERROR

        if mode.progress_bar is not None:
            mode.progress_bar.stop()
        report_path = get_abspath(config.output.path)
        self._print_summary(mode, findings, errors, datetime.now() - startup_time, report_path)

        if config._benchmarking_mode is True:
            return findings, errors, timings, mode._oneshot_file

        self._write_report(mode, findings, report_path)
        self._say_goodbye(findings)
        self._release(mode)

        if len(findings) > 0 and config.return_code_if_findings:
            return ReturnCodes.FINDINGS_DETECTED

        return ReturnCodes.OK

    @staticmethod
    def _refuse_json_output() -> None:  # pragma: nocover
        console.print('\n')
        console.print(
            Align(
                Panel(
                    'The internal JSON report format was deprecated in 2.1 and is removed in 2.2.0.\n'
                    'Use --outformat sarif (the default) or dojo-sarif.',
                    padding=(1, 2),
                    title=Text('SARIF IS NOW DEFAULT OUTPUT FORMAT', style='reverse'),
                    highlight=True,
                    subtitle=Text(' --outformat sarif ', style='reverse'),
                    title_align='center',
                    width=90,
                    subtitle_align='center',
                    box=box.HEAVY,
                    style='black on orange_red1',
                    expand=False,
                ),
                align='center',
            )
        )

    def _print_plan(self) -> None:  # pragma: nocover
        config = self.config
        console.rule(
            f'Planning a scan against {config.workdir_path} using {config.process_count} process(es)', characters='='
        )
        console.line()
        if config.disable_masking is True:
            console.print(
                '[bold red]:warning: SECRETS MASKING IS DISABLED. REPORT WILL CONTAIN SECRETS IN PLAINTEXT. BE CAREFUL!\n',
                justify='center',
            )
        else:
            console.print(
                '[bold green]:warning: SECRETS MASKING IS ENABLED. FINGERPRINTS ARE UNAFFECTED\n(downstream ASPM deduplication will work normally)\n',
                justify='center',
            )

        if config.return_code_if_findings is True:
            console.print(
                f'[bold yellow]:warning:[/bold yellow] The tool will return code of {ReturnCodes.FINDINGS_DETECTED} if any findings are detected\n'
            )

    def _print_summary(
        self, mode: CliScanMode, findings: List[Finding], errors: Dict[str, List[str]], elapsed, report_path: str
    ) -> None:  # pragma: nocover
        console.line()
        console.print('[bold green]Scanning finished successfully', justify='center')
        console.line()

        console.rule('', characters='=')
        console.line()
        table = Table(
            title=Text('REPORT SUMMARY'),
            box=box.HORIZONTALS,
            show_header=False,
            row_styles=['blink'],
            style='dim',
            width=80,
        )
        table.add_column()
        table.add_column(justify='right')
        table.add_row(
            Align('Processed Files (Tokens)', vertical='middle'),
            f'{str(len(mode.filepaths))} ({mode.stats.tokens_processed})',
        )
        table.add_row(Align('Elapsed', vertical='middle'), f'{elapsed.total_seconds():.1f}s')
        errors_line_color = '[bold red]' if len(errors.keys()) > 0 else '[bold green]'
        table.add_row(
            Align(f'{errors_line_color}File Errors', vertical='middle'),
            f'{errors_line_color}{mode.stats.failed_files}',
        )
        table.add_row()

        findings_line_color = '[bold red]' if len(findings) > 0 else '[bold green]'
        table.add_row(
            Align(f'{findings_line_color}Potential Findings', vertical='middle'),
            f'{findings_line_color}{str(len(findings))}',
        )
        table.add_row(Align(f'Report Location ({self.config.output.type})', vertical='middle'), report_path)
        console.print(Align(table, align='center'))

    def _write_report(self, mode: CliScanMode, findings: List[Finding], report_path: str) -> None:
        # sarif and dojo-sarif are the same document; built before the file is opened, so a failure leaves no
        # truncated report behind
        report = (
            DojoSarifResponseBuilder()
            .with_current_mode(mode)
            .with_findings_list(findings)
            .with_masking_enabled(not self.config.disable_masking)
            .build()
        )
        with open(report_path, 'w+') as f:
            f.write(to_json(report))

    def _say_goodbye(self, findings: List[Finding]) -> None:  # pragma: nocover
        if len(findings) > 0 and self.config.disable_masking:
            console.print(
                '[bold red]:warning: SECRETS MASKING WAS DISABLED, THE REPORT CONTAINS POTENTIAL SECRETS IN PLAINTEXT.\nBE CAREFUL!',
                justify='center',
            )

        console.line()
        console.print(
            Align('[italic]Any missed secret or massive false positive rate is potentially a bug', align='center')
        )
        console.print(Align('[italic]So feel free to report bugs and difficulties here', align='center'))
        console.print(Align('[italic]https://github.com/ntoskernel/deepsecrets/issues', align='center'))
        console.line()
        console.print(Align('[bold green]FINISHED', align='center'))
        console.line(2)

    @staticmethod
    def _release(mode: CliScanMode) -> None:
        mode.dispose()
        # the pool and the manager are gone: wait for the forkserver, so whoever waits for this process sees the
        # workers' CPU time (KI-CLI-42)
        stop_forkserver()
