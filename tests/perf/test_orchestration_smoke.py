import os
import time
from unittest.mock import Mock

import pytest

from deepsecrets.config import Config, Output
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.scan_modes.cli import CliScanMode


@pytest.mark.skipif(
    os.environ.get('DEEPSECRETS_PERF') != '1',
    reason='Run with DEEPSECRETS_PERF=1 for manual benchmarking',
)
def test_baseline_fixtures_scan_duration(capsys):
    config = Config()
    config.set_workdir('tests/fixtures')
    config.set_process_count(4)
    config.engines.append(RegexEngine)
    config.engines.append(SemanticEngine)
    config.add_ruleset(RegexRulesetBuilder, ['deepsecrets/rules/regexes.json'])
    config.output = Output(type='json', path='/tmp/ds_baseline.json')

    mode = CliScanMode(config=config)
    mode.progress_bar = Mock()
    mode.progress_bar.add_task.return_value = 0

    start = time.perf_counter()
    findings = mode.run()
    elapsed = time.perf_counter() - start
    mode.dispose()

    with capsys.disabled():
        print(f'\n[BENCH] files={len(mode.filepaths)} findings={len(findings)} elapsed={elapsed:.3f}s')
