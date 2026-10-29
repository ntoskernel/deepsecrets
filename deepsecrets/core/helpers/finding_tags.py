"""Finding tags: what sort of secret a finding is, where its confidence says how likely it is one. A tag never changes
what is reported: --exclude-tags drops the findings that carry one, and SARIF carries them in a result's `tags`
property. See docs/private/research/2.3-design.md, P5.

Where each tag is set:
- `weak-password`: by SemanticEngine on every S106 finding, a weak value under a name people choose a value for;
- `publishable`: by scoring rules that carry `"tag": "publishable"` (SEM_VAR_TAG_PUBLISHABLE on a variable's name,
  RC_TAG_PUBLISHABLE and SEM_VAR_TAG_PUBLISHABLE_VALUE on a value): keys made to ship to clients;
- `test-context`: by ScanMode, on the merged findings, from the path relative to the target directory
  (tag_test_context below)."""

from typing import Dict, Iterable

import regex as re

from deepsecrets.core.model.finding import Finding

WEAK_PASSWORD = 'weak-password'
PUBLISHABLE = 'publishable'
TEST_CONTEXT = 'test-context'
# the names --exclude-tags accepts
TAGS = (WEAK_PASSWORD, PUBLISHABLE, TEST_CONTEXT)

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


def in_test_context(relative_path: str) -> bool:
    return TEST_CONTEXT_PATH.search(relative_path) is not None


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
