import pytest
from jschema_to_python.to_json import to_json

from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.response.base import BaseResponseBuilder
from deepsecrets.core.model.response.builtin import BuiltinFormatResponseBuilder
from deepsecrets.core.model.response.dojo_sarif import DojoSarifResponseBuilder
from deepsecrets.core.model.rules.rule import Rule

# A secret that starts mid-line and continues on the next line
ML_LINE_1 = 'config: {"private_key": "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAwwuwmtxV5vZwAu'
ML_LINE_2 = 'ZKSEPrgddDb7Qv8eeX0PnCtS-----END RSA PRIVATE KEY-----"}'
ML_KEY_FRAGMENT = 'MIIEowIBAAKCAQEAwwuwmtxV5vZwAu'


def _finding_for(content: str, detection: str) -> Finding:
    file = File(path='/tmp/masking/config.yml', content=content)
    start = content.index(detection)
    finding = Finding(
        rules=[Rule(id='S26', name='Private key', confidence=10)],
        detection=detection,
        start_offset=start,
        end_offset=start + len(detection),
    )
    finding.map_on_file(relative_start=0, file=file)
    return finding


@pytest.fixture
def multiline_finding() -> Finding:
    content = f'{ML_LINE_1}\n{ML_LINE_2}\n'
    start = content.index('-----BEGIN')
    end = content.index('KEY-----"}') + len('KEY-----')
    return _finding_for(content, content[start:end])


def _masked_first_line() -> str:
    start = ML_LINE_1.index('-----BEGIN')
    return ML_LINE_1[:start] + '*' * (len(ML_LINE_1) - start)


@pytest.fixture
def base_response_builder():
    return BaseResponseBuilder()


@pytest.mark.parametrize(
    "snippet, detection, expected",
    [
        (
            "hellomydearfriends",
            "hellomydearfriends",
            "hell*********iends",
        ),
        (
            "abcdefgh",
            "abcdefgh",
            "ab****gh",
        ),
        (
            "abcde",
            "abcde",
            "a***e",
        ),
        (
            "x",
            "x",
            "*",
        ),
        (
            "xy",
            "xy",
            "*y",
        ),
        (
            "xyz",
            "xyz",
            "**z",
        ),
        (
            "hello",
            "",
            "hello",
        ),
        (
            "error: secret_password_123 found",
            "secret_password_123",
            "error: secr**********d_123 found",
        ),
        (
            "token: 123456, old_token: 123456",
            "123456",
            "token: 1***56, old_token: 1***56",
        ),
        (
            "confidential: admin master 77",
            "admin master 77",
            "confidential: adm********r 77",
        ),
        (
            "hello world",
            "not_found",
            "hello world",
        ),
    ],
)
def test_masking(base_response_builder, snippet, detection, expected):
    assert base_response_builder._mask(snippet, detection) == expected


def test_sarif_context_masks_multiline_detection(multiline_finding: Finding):
    assert multiline_finding.start_line_number == 1
    assert multiline_finding.end_line_number == 2

    region = DojoSarifResponseBuilder().get_context_region(finding=multiline_finding, masking=True)

    assert region.snippet.text == _masked_first_line()
    assert ML_KEY_FRAGMENT not in region.snippet.text


def test_sarif_context_unmasked_when_masking_disabled(multiline_finding: Finding):
    region = DojoSarifResponseBuilder().get_context_region(finding=multiline_finding, masking=False)
    assert region.snippet.text == ML_LINE_1


def test_sarif_report_does_not_leak_multiline_secret(multiline_finding: Finding):
    report = DojoSarifResponseBuilder().with_findings_list([multiline_finding]).with_masking_enabled(True).build()
    assert ML_KEY_FRAGMENT not in to_json(report)


def test_sarif_context_single_line_masking_unchanged():
    finding = _finding_for('password = "hunter2hunter2"\n', 'hunter2hunter2')
    region = DojoSarifResponseBuilder().get_context_region(finding=finding, masking=True)
    assert region.snippet.text == 'password = "hun*******ter2"'


def test_builtin_line_masks_multiline_detection(multiline_finding: Finding):
    report = BuiltinFormatResponseBuilder().with_findings_list([multiline_finding]).with_masking_enabled(True).build()

    reported = report[multiline_finding.file.path][0]
    assert reported['line'] == _masked_first_line()
    assert ML_KEY_FRAGMENT not in reported['line']


def test_builtin_single_line_masking_unchanged():
    finding = _finding_for('password = "hunter2hunter2"\n', 'hunter2hunter2')
    report = BuiltinFormatResponseBuilder().with_findings_list([finding]).with_masking_enabled(True).build()

    reported = report[finding.file.path][0]
    assert reported['line'] == 'password = "**************"'
    assert reported['string'] == '**************'
