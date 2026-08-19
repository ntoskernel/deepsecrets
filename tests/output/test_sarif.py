from unittest.mock import Mock
from jschema_to_python.to_json import to_json
import pytest

from deepsecrets.config import Config, Output
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.response.dojo_sarif import DojoSarifResponseBuilder
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
    mode.progress_bar = Mock()
    mode.progress_bar.add_task.return_value = 0
    mode.progress_bar.task_ids = []

    findings = []

    for file in mode.filepaths:
        findings.extend(mode._per_file_analyzer(mode.analyzer_bundle(), file, 0, {}).findings)

    '''
    # checking through the 'run' method
    # false findings checked at the end
    findings = []
    findings = mode.run()
    '''

    sarif_data = (
        DojoSarifResponseBuilder()
        .with_current_mode(mode)
        .with_findings_list(findings)
        .with_masking_enabled(not config.disable_masking)
        .build()
    )

    sarif_response = to_json(sarif_data)
    assert sarif_data is not None
    assert sarif_response is not None

    assert type(sarif_data.runs[0].original_uri_base_ids) is dict
