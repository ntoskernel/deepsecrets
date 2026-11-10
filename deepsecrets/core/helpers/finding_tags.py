"""Finding tags: what sort of secret a finding is, where its confidence says how likely it is one. A tag never changes
what is reported: --exclude-tags drops the findings that carry one, and SARIF carries them in a result's `tags`
property. See docs/private/research/2.3-design.md, P5.

Where each tag is set:
- `weak-password`: by SemanticEngine on every S106 finding, a weak value under a name people choose a value for;
- `publishable`: by scoring rules that carry `"tag": "publishable"` (SEM_VAR_TAG_PUBLISHABLE on a variable's name,
  RC_TAG_PUBLISHABLE and SEM_VAR_TAG_PUBLISHABLE_VALUE on a value): keys made to ship to clients;
- `test-context`: by ScanMode, on the merged findings, from the path relative to the target directory
  (tag_test_context below);
- `recorded-traffic`: the same way, for recorded HTTP traffic (VCR cassettes, session recordings, HAR files).

The recorded-traffic context also lowers S105, the one place a path changes a confidence (apply_path_context)."""

from typing import Dict, Iterable

import regex as re

from deepsecrets.config import RECORDED_TRAFFIC_MAX_CONFIDENCE
from deepsecrets.core.model.finding import Finding

WEAK_PASSWORD = 'weak-password'
PUBLISHABLE = 'publishable'
TEST_CONTEXT = 'test-context'
RECORDED_TRAFFIC = 'recorded-traffic'
# the names --exclude-tags accepts
TAGS = (WEAK_PASSWORD, PUBLISHABLE, TEST_CONTEXT, RECORDED_TRAFFIC)

# A test, spec, fixture, mock, example or sample path: one of those words as a directory or as a word of the file
# name, delimited by / \ . _ or - (tests/, __mocks__/, integration-tests/, client_test.go, user.spec.ts, fixtures.json,
# .env.example, settings.sample), or a camel-case class file (ClientTest.java, UserSpec.scala). Not the words inside
# others (latest/, contest.py, attestation/, sampler.py), nor a .spec or .test extension (an RPM spec file).
# It reads the path relative to the target directory, so where the checkout sits does not matter, unlike the path rules
# SEM_VAR_FILE_PATHS and RC_TEST_PATH, which read the absolute one (KI-ENG-25)
TEST_CONTEXT_PATH = re.compile(
    r'(?:^|[/\\._-])(?:tests?|testing|testdata|specs?|fixtures?|mocks?)(?=[/\\._-])'
    r'|(?:^|[/\\._-])(?:examples?|samples?)(?=[/\\._-]|$)'
    r'|(?-i:[a-z\d](?:Tests?|Spec|Mocks?)\.\w+$)',
    re.IGNORECASE,
)


# Recorded HTTP traffic: a cassettes, recordings, session-records or vcr directory (fixtures/vcr_cassettes/,
# tests/recordings/, SessionRecords/), or a HAR file. Values there are mostly per-response tokens, not credentials:
# beyond SecretBench's labels, 108 noise units to 10 secrets among 2.3's S105 findings at MEDIUM and above
RECORDED_TRAFFIC_PATH = re.compile(
    r'(?:^|[/\\._-])(?:cassettes?|recordings?|sessionrecords|vcr)[/\\]|\.har$',
    re.IGNORECASE,
)


def in_test_context(relative_path: str) -> bool:
    return TEST_CONTEXT_PATH.search(relative_path) is not None


def in_recorded_traffic(relative_path: str) -> bool:
    return RECORDED_TRAFFIC_PATH.search(relative_path) is not None


def tag_test_context(findings: Iterable[Finding]) -> None:
    """Tags `test-context` on every finding whose file sits in a test, spec, fixture, mock, example or sample path."""
    answers: Dict[str, bool] = {}
    for finding in findings:
        path = finding.file.relative_path if finding.file is not None else None
        if not path:
            continue
        if path not in answers:
            answers[path] = in_test_context(path)
        if answers[path]:
            finding.add_tag(TEST_CONTEXT)


def apply_path_context(findings: Iterable[Finding]) -> None:
    """What a finding's relative path says: `test-context`, and `recorded-traffic` with S105 lowered into the LOW tier.
    A typed rule on the same span (a regex match) keeps its confidence and may then name the finding."""
    findings = list(findings)
    tag_test_context(findings)
    answers: Dict[str, bool] = {}
    for finding in findings:
        path = finding.file.relative_path if finding.file is not None else None
        if not path:
            continue
        if path not in answers:
            answers[path] = in_recorded_traffic(path)
        if not answers[path]:
            continue
        finding.add_tag(RECORDED_TRAFFIC)
        # rules compare by id, so the change is tracked, not found by comparing lists
        lowered = [r.id == 'S105' and r.confidence > RECORDED_TRAFFIC_MAX_CONFIDENCE for r in finding.rules]
        if any(lowered):
            finding.rules = [
                rule.model_copy(update={'confidence': RECORDED_TRAFFIC_MAX_CONFIDENCE}) if low else rule
                for rule, low in zip(finding.rules, lowered)
            ]
            if finding.final_rule is not None:
                finding.choose_final_rule()
