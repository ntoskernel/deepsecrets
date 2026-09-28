import pytest

from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.utils.file_analyzer import FileAnalyzer


@pytest.mark.fixture_file_path('1.toml')
def test_file_analyzer(file):
    file_analyzer = FileAnalyzer(file)

    lex = LexerTokenizer(deep_token_inspection=True)
    semantic_engine = SemanticEngine(subengine=None)
    file_analyzer.add_engine(engine=semantic_engine, tokenizers=[lex])

    findings = file_analyzer.process()
    assert findings is not None


def _builtin_bundle(workdir):
    from deepsecrets.core.model.internal.processing import AnalyzerBundle
    from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
    from deepsecrets.core.rulesets.regex_candidate_scoring import RegexCandidateScoringRulesetBuilder
    from deepsecrets.core.rulesets.variable_scoring import VariableScoringRulesetBuilder
    from deepsecrets.core.utils.fs import get_path_inside_package

    rulesets = {}
    for builder, path in (
        (RegexRulesetBuilder, 'rules/regexes.json'),
        (RegexCandidateScoringRulesetBuilder, 'rules/regex_candidate_scoring_rules.json'),
        (VariableScoringRulesetBuilder, 'rules/variable_scoring_rules.json'),
    ):
        rulesets[builder.ruleset_name] = builder().with_rules_from_file(get_path_inside_package(path)).rules
    return AnalyzerBundle(workdir=str(workdir), engines={'regex': True, 'semantic': True}, rulesets=rulesets)


@pytest.mark.parametrize(
    'first',
    [
        'x = "AKIAAAAABBBBBCCCCCDD"',  # a regex candidate, rejected (not random) under a name that proves nothing
        'label = "Zx8vQ2mK7pLr4NtY"',  # no finding at all
    ],
)
def test_a_value_seen_under_another_name_is_still_evaluated(tmp_path, first):
    # KI-ENG-08: the per-file value cache keyed on the content alone, so the second line was skipped
    from deepsecrets.scan_modes.cli import CliScanMode

    value = first.split('"')[1]
    target = tmp_path / 'settings.py'
    target.write_text(f'{first}\naws_secret_access_key = "{value}"\n')
    result = CliScanMode._per_file_analyzer(_builtin_bundle(tmp_path), str(target), 1, None)

    reported = [f for f in result.findings if f.detection == value]
    assert reported and {f.start_line_number for f in reported} == {2}
