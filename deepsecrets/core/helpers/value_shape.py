"""What a value's shape says it holds, computed in code: a file name or a path (`file_name`), a version (`version`), or
an ascending run such as `123456` or `abcdef` (`sequence`). The flags are space-separated in `Context.value_shape`,
which scoring rules read through the `VALUE_SHAPE` target (rules/variable_scoring_rules.json and, for regex candidates,
rules/regex_candidate_scoring_rules.json); see docs/private/research/2.3-design.md, P1."""

import string

import regex as re

FILE_NAME = 'file_name'
VERSION = 'version'
SEQUENCE = 'sequence'

# A file name is a name, a dot and a one-case extension of up to 10 characters with a letter in it: main.log,
# IMG_2041.JPG, q3.parquet, x.7z. None of the encodings random secrets are written in (base64, hex, base32, base58) has
# a dot, and the dotted tokens (JWT, Discord, Vault, Mapbox) end in a long, mixed-case random part, so no list of
# extensions is needed. Checked piece by piece rather than with one pattern, which backtracks quadratically over a long
# dotted value
EXTENSION = re.compile(r'(?=\d*[a-z])[a-z\d]{1,10}|(?=\d*[A-Z])[A-Z\d]{1,10}')
WORD_CHARACTER = re.compile(r'\w')
NOT_NAME_CHARACTER = re.compile(r'[^\w\-.~+%]')
# what the path before the name may hold. Not `=`, `;`, `,`, `?` or `&`: a connection string or a query
# (`AccountKey=…;EndpointSuffix=core.windows.net`) ends in a host, not a file
NOT_PATH_CHARACTER = re.compile(r'[^\w\-.~+%:/\\]')
# three dotted numbers: 3.0.17, 2.14.1-rc1. An IP address has four and does not count
VERSION_PATTERN = re.compile(r'(?<![\d.])\d+\.\d+\.\d+(?!\.?\d)')
WHITESPACE = re.compile(r'\s')

# An ascending run has the highest entropy a string of its length can have, so neither the entropy score nor a
# randomness measure sees it. 6 characters keep the five-character chance runs of short hex values out; a random
# 40-character hex value still holds a run of 6 about once in 50,000. Descending runs are left out (one more look-alike
# on SecretBench, no secret). Every run of 6 or more holds one of these windows, so the test is a substring search:
# linear in the value, about 3 us for a short one
SEQUENCE_LENGTH = 6
SEQUENCE_WINDOWS = tuple(
    alphabet[start : start + SEQUENCE_LENGTH]
    for alphabet in (string.digits, string.ascii_lowercase, string.ascii_uppercase)
    for start in range(len(alphabet) - SEQUENCE_LENGTH + 1)
)


def value_shape(value: str) -> str:
    """The flags of a value's shape, space-separated; '' when it has none. A value with whitespace has none (a PGP
    block with a `Version:` header is still judged). A URL or an address (`://`, `@`), or a value without a dot, is
    never a file name or a version, but can hold a sequence."""
    if WHITESPACE.search(value):
        return ''

    flags = []
    if '.' in value and '://' not in value and '@' not in value:
        if is_file_name(value):
            flags.append(FILE_NAME)
        if VERSION_PATTERN.search(value):
            flags.append(VERSION)
    if has_sequence(value):
        flags.append(SEQUENCE)
    return ' '.join(flags)


def is_file_name(value: str) -> bool:
    """A file name, alone or at the end of a / or \\ path: `logo.png`, `/srv/tls/server.key`, `backups/x/main.log`."""
    cut = max(value.rfind('/'), value.rfind('\\'))
    name, dot, extension = value[cut + 1 :].rpartition('.')
    if not dot or not name or EXTENSION.fullmatch(extension) is None:
        return False
    if WORD_CHARACTER.fullmatch(name[-1]) is None or NOT_NAME_CHARACTER.search(name):
        return False
    return cut < 0 or NOT_PATH_CHARACTER.search(value, 0, cut) is None


def has_sequence(value: str) -> bool:
    """Whether 6 or more consecutive characters each follow the previous by one code point, all digits or all letters
    of one case: `123456`, `abcdef`, `xoxb-123456789012`. Not `789abc`, `ABCdef` or `654321`."""
    return len(value) >= SEQUENCE_LENGTH and any(window in value for window in SEQUENCE_WINDOWS)
