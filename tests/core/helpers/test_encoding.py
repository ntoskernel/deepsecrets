"""Encoded values: payload, foreign share, randomness against a random string, checksum. Values are synthetic."""

import base64
import hashlib
import random
import textwrap
import time

import pytest

from deepsecrets.core.helpers import encoding
from deepsecrets.core.helpers.entropy import EntropyHelper

RANDOM = random.Random(7)
BODY = base64.b64encode(bytes(RANDOM.randrange(256) for _ in range(1190))).decode()
LINES = textwrap.wrap(BODY, 64)


def base58check(payload: bytes) -> str:
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number, text = int.from_bytes(raw, 'big'), ''
    while number:
        number, digit = divmod(number, 58)
        text = encoding.BASE58[digit] + text
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + text


def randomness(value, declared=None):
    return encoding.randomness(value, EntropyHelper.get_for_string(value), declared)


FORMS = {
    'pem': '\n'.join(LINES),
    'encrypted pem': 'Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n' + '\n'.join(LINES),
    'json string': '\\nProc-Type: 4,ENCRYPTED\\nDEK-Info: AES-128-CBC,0123456789ABCDEF\\n\\n'
    + '\\n'.join(LINES)
    + '\\n',
    'json, escaped slashes': '\\n'.join(line.replace('/', '\\/') for line in LINES),
    'java concatenation': '\\n" +\n' + '\n'.join(f'    "{line}\\n" +' for line in LINES) + '\n    "',
    'java, + first': '\n'.join(f'    + "{line}\\n"' for line in LINES),
    'one-line concatenation': ' + '.join(f'"{line}"' for line in LINES),
    'go concatenation': '\n'.join(f'\t"{line}\\n" +' for line in LINES) + '\n\t""',
    'python list': '\n'.join(f"    '{line}'," for line in LINES),
    'c# interpolation': '\n'.join(f'$"{line}{{lineEnding}}" +' for line in LINES),
    'vb concatenation': '\n'.join(f'"{line}" & vbCrLf & _' for line in LINES),
    'java line separator': '\n'.join(f'    "{line}" + System.lineSeparator() +' for line in LINES),
    'php line ending': '\n'.join(f'    "{line}" . PHP_EOL .' for line in LINES),
    'php, dot first': '\n'.join(f'    . "{line}\\n"' for line in LINES),
    'xml entities': '&#13;\n'.join(LINES),
    'xml hex entities': '&#xD;&#xA;'.join(LINES),
    'html line breaks': '<br>\n'.join(LINES),
    'shell comment': '\n'.join(f'# {line}' for line in LINES),
    'block comment': '\n'.join(f' * {line}' for line in LINES),
    'markdown quote': '\n'.join(f'> {line}' for line in LINES),
    'removed in a diff': '\n'.join(f'-{line}' for line in textwrap.wrap(BODY, 40)),
    'yaml block': '\n'.join(f'    {line}' for line in LINES),
}


def test_another_private_keys_armour_inside_a_body_is_dropped():
    # a diff that removes one key and adds another: the removed key's END line (------END…) is not an end marker to
    # the key rules, so the match runs into the added key. Both halves are key material
    removed = '\n'.join(f'-{line}' for line in LINES[:12])
    added = '\n'.join(f'+{line}' for line in LINES[12:])
    written = removed + '\n------END RSA PRIVATE KEY-----\n+-----BEGIN RSA PRIVATE KEY-----\n' + added
    assert encoding.foreign_share(encoding.payload(written), 'base64') == 0


@pytest.mark.parametrize('written', FORMS.values(), ids=FORMS.keys())
def test_the_payload_is_the_same_however_the_body_is_written(written):
    assert encoding.payload(written) == BODY


@pytest.mark.parametrize(
    'written',
    [
        '\\n" + "\\n" + key.replace(/(.{64})/g, "$1\\n") + "\\n',
        '\\n";\n    result += base64.encode(chunk);\n    result += "\\n',
        'MIIEpAIBAAKCAQEA...\n...your private key goes here, one line per 64 characters...',
        '\nBad key, the certificate is fine\n-----END RSA PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\n' + LINES[0],
    ],
    ids=['code building a key', 'code appending chunks', 'ellipsis and prose', 'a match across two blocks'],
)
def test_code_and_placeholders_between_the_markers_stay_foreign(written):
    assert encoding.foreign_share(encoding.payload(written), 'base64') > 0.02


def test_an_ellipsis_before_the_closing_quote_stays_foreign():
    # a dot is decoration next to a quote only after it (PHP's "…" . PHP_EOL), not before it: "MIIE..." is truncated
    assert encoding.foreign_share(encoding.payload('"' + LINES[0][:20] + '..."'), 'base64') > 0.02


@pytest.mark.parametrize('text', ['-' * 20000, '"' + ' ' * 20000, '-----BEGIN RSA PRIVATE KEY-----\n' + '-' * 20000])
def test_long_runs_take_linear_time(text):
    # a long run of dashes or of blanks after a quote used to take seconds (every start of the run was retried)
    started = time.perf_counter()
    encoding.payload(text)
    assert time.perf_counter() - started < 0.5


def test_the_foreign_share_counts_characters_outside_the_alphabet():
    assert encoding.foreign_share(BODY, 'base64') == 0
    assert encoding.foreign_share('MIIEpAIBAAKCAQEA...' + 'A' * 81, 'base64') == 0.03
    assert encoding.foreign_share('AKIA0000000000000000', 'base32') == 0.8
    assert encoding.foreign_share('anything at all', None) == 0


def test_the_expected_entropy_of_a_random_string():
    assert encoding.expected_entropy(1, 64) == 0
    lengths = [encoding.expected_entropy(n, 64) for n in (16, 64, 256, 1024, 2048)]
    assert lengths == sorted(lengths) and lengths[-1] < 6
    # the approximation takes over where the exact sum stops, without a step
    edge = encoding.EXACT_UP_TO
    assert abs(encoding.expected_entropy(edge, 64) - encoding.expected_entropy(edge + 1, 64)) < 1e-3


def test_randomness_is_about_one_for_a_random_value_and_low_for_structure():
    assert randomness(BODY, 'base64') > 0.98
    assert randomness('A' * 1024, 'base64') == 0
    assert randomness('AKIAAAAAAAAAAAAAAAAA', 'base32') < 0.75
    assert randomness('xoxb-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXXXX') < 0.75


@pytest.mark.parametrize(
    'value, symbols',
    [('0123456789abcdef', 16), ('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 32), ('xyz123', 36), ('aB3', 62), ('aB3-_', 64)],
)
def test_without_an_encoding_the_alphabet_is_read_from_the_value(value, symbols):
    assert encoding.symbols(value, None) == symbols


def test_a_base58check_value_carries_its_checksum():
    key = base58check(b'\x80' + bytes(RANDOM.randrange(256) for _ in range(32)))
    assert len(key) == 51 and key[0] == '5'
    assert encoding.checksum(key, 'base58check') == 'valid'
    altered = key[:-1] + ('2' if key[-1] != '2' else '3')
    assert encoding.checksum(altered, 'base58check') == 'invalid'
    assert encoding.checksum(key[:-1] + '0', 'base58check') == 'invalid'  # 0 is not base58
    assert encoding.checksum(key, 'base64') == 'none'
