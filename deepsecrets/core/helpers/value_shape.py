"""What a value's shape says it holds, computed in code: a file name or a path (`file_name`), or a version (`version`).
The flags are space-separated in `Context.value_shape`, which scoring rules read through the `VALUE_SHAPE` target
(rules/variable_scoring_rules.json); see docs/private/release-notes/2.2.1.md."""

import regex as re

FILE_NAME = 'file_name'
VERSION = 'version'

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


def value_shape(value: str) -> str:
    """The flags of a value's shape, space-separated; '' when it has none. A value with whitespace has none (a PGP
    block with a `Version:` header is still judged), and neither has a URL or an address (`://`, `@`)."""
    if '.' not in value or '://' in value or '@' in value or WHITESPACE.search(value):
        return ''

    flags = []
    if is_file_name(value):
        flags.append(FILE_NAME)
    if VERSION_PATTERN.search(value):
        flags.append(VERSION)
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
