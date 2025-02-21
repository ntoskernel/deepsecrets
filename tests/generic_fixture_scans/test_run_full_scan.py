from unittest.mock import Mock
import pytest

from deepsecrets.config import Config, Output
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.rulesets.false_findings import FalseFindingsBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.scan_modes.cli import CliScanMode


@pytest.fixture()
def config() -> Config:
    config = None
    config = Config()
    config.set_workdir('tests/fixtures')
    config.engines.append(RegexEngine)
    config.engines.append(SemanticEngine)
    config.add_ruleset(RegexRulesetBuilder, ['tests/fixtures/regexes.json'])
    config.add_ruleset(FalseFindingsBuilder, ['tests/fixtures/false_findings.json'])
    config.output = Output(type='json', path='tests/1.json')
    return config


def test_everything(config: Config) -> None:
    mode = CliScanMode(config=config)
    mode.progress_bar = Mock()
    mode.progress_bar.add_task.return_value = 0
    findings = mode.run()

    detections = [finding.detection for finding in findings]
    assert 'bAicxJVa5uVY7MjDlapthw' in detections
    assert 'nacc6opq' in detections
    assert 'xBfiGBARuoQ9HoLWtw1HwbrkPurCI8v7fO7RJDaZFp7gkBqWxRjQc9WemTVrwu1c' in detections