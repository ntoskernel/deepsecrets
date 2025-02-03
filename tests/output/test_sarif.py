import pytest

from deepsecrets.config import Config, Output
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.finding import FindingResponse
from deepsecrets.core.rulesets.false_findings import FalseFindingsBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.scan_modes.cli import CliScanMode

FP_TO_BE_EXCLUDED = '/app/tests/fixtures/service.postman_collection.json'

@pytest.fixture()
def config() -> Config:
    config = None
    config = Config()
    config.set_workdir('tests/fixtures')
    config.engines.append(RegexEngine)
    config.engines.append(SemanticEngine)
    config.add_ruleset(RegexRulesetBuilder, ['tests/fixtures/regexes.json'])
    config.add_ruleset(FalseFindingsBuilder, ['tests/fixtures/false_findings.json'])
    config.output = Output(type='dojo-sarif', path='tests/1.json')
    return config


def test_dojo_sarif(config: Config) -> None:
    mode = CliScanMode(config=config)
    findings = []
    for file in mode.filepaths:
        findings.extend(mode._per_file_analyzer(mode.analyzer_bundle(), file))

    findings = []
    findings = mode.run()

    sarif_response = FindingResponse.dojo_sarif_from_list(findings)
    assert sarif_response is not None