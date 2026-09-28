"""What an encoded value is made of: its payload, the share of it outside its alphabet, how random it is for its
length, and whether its checksum holds. A regex rule declares the encoding on its value group (`"encoding": "base64"`
in a `match_rules` entry); see docs/private/research/regex-precision-and-gap.md."""

import hashlib
from functools import lru_cache
from math import exp, lgamma, log, log1p, log2
from typing import Optional

import regex as re

BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
ALPHABETS = {
    'base64': frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='),
    'base32': frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567='),
    'hex': frozenset('0123456789abcdefABCDEF'),
    'base58check': frozenset(BASE58),
}
# the symbols a random value of the encoding draws from (padding and the two cases of hex are not extra symbols)
SYMBOLS = {'base64': 64, 'base32': 32, 'hex': 16, 'base58check': 58}

# The payload is read line by line: what surrounds an encoded value in source code sits at the ends of its lines
# (indentation, quotes, a comment marker, a diff sign, a concatenation, a line continuation), while code between two
# key markers has foreign characters inside its lines. Decoration is stripped, the inside is kept as it is.

# the armour of another block inside a body: the match ran across blocks. Another private key's armour (a key removed
# and one added in a diff, two keys in a row) goes like a header line; any other block's (a certificate, a public key)
# stays foreign, whatever its edges
# (a match starts at the first dash of a run: trying every dash of a long run would take quadratic time)
ARMOUR = re.compile(r'(?<!-)-{3,}\s*(?:BEGIN|END)\b[^\n]*?-{3,}', re.IGNORECASE)
# what writes a line break inside source text: an escape (once or twice), an XML or HTML entity, <br>, a language's
# newline constant
LINE_BREAK = re.compile(
    r'\\{1,2}[rn]|&#1[03];|&#x0?[da];|<br\s*/?>|'
    r'\b(?:vbCrLf|vbNewLine|vbLf|Environment\.NewLine|PHP_EOL|os\.linesep)\b|\bSystem\.lineSeparator\(\)',
    re.IGNORECASE,
)
# what escaping leaves (\/ in JSON, \" and \\ in string literals): a backslash is never part of an encoded value
BACKSLASH = re.compile(r'\\+')
# an interpolated name standing for a line break: {lineEnding}, ${nl}, #{eol}
PLACEHOLDER = re.compile(r'[$#]?\{[A-Za-z_][\w.]*(?:\(\))?\}')
# an armour header (Proc-Type, DEK-Info, Version, Comment…): no line of an encoded payload has a colon
HEADER_LINE = re.compile(r'^[^\w\n]*[A-Za-z][A-Za-z0-9-]*:[^\n]*$', re.MULTILINE)
# two string literals joined: "…" + "…" (Java, JS), "…" . "…" (PHP), "…" & "…" (VB), '…', '…' (a list), "…" $"…" (C#)
# (the whitespace after the operator belongs to it: two adjacent \s* would take quadratic time on a long run)
CONCATENATION = re.compile(r'["\'`]\s*(?:[+.,&]\s*)?[$@]?["\'`]')
# decoration at the start and the end of a line. A + (Java, JS) or a . (PHP) is decoration only next to a quote
# (+ "…" starting a line, "…" + ending one): elsewhere a + is base64, and a dot before the closing quote is an
# ellipsis (MIIE...), a truncated key rather than decoration
LEAD = re.compile(r'^(?:[ \t"\'`#*;>!|$@(\[,&-]|[+.](?=[ \t]*["\'`$@]))+', re.MULTILINE)
TRAIL = re.compile(r'(?:[ \t"\'`,;&_)\]|>-]|(?<=["\'`][ \t]*)[+.])+$', re.MULTILINE)
# a line left with nothing but the concatenation sign
LONE_PLUS = re.compile(r'^[ \t]*[+.][ \t]*$', re.MULTILINE)
WHITESPACE = re.compile(r'\s+')

HEX = re.compile(r'[0-9a-f]+|[0-9A-F]+')
BASE32 = re.compile(r'[A-Z2-7]+')
CLASSES = ((re.compile(r'\d'), 10), (re.compile('[a-z]'), 26), (re.compile('[A-Z]'), 26))
ALPHANUMERIC = re.compile(r'[A-Za-z0-9]')
# up to this length the expected entropy of a random string is summed exactly, beyond it approximated
EXACT_UP_TO = 2048


def _other_armour_foreign(armour: re.Match) -> str:
    return '' if 'PRIVATE' in armour.group(0).upper() else '~' * len(armour.group(0))


def payload(text: str) -> str:
    """The encoded value alone. Line breaks written as escapes, entities or constants become line breaks, header lines
    go, and each line loses the decoration at its ends. A key body in a PEM file, a JSON string, a Java, Go, PHP, VB or
    C# concatenation, a comment, a diff or an XML document gives the same payload."""
    text = ARMOUR.sub(_other_armour_foreign, text)
    text = LINE_BREAK.sub('\n', text)
    text = BACKSLASH.sub('', text)
    text = PLACEHOLDER.sub('', text)
    text = HEADER_LINE.sub('', text)
    text = CONCATENATION.sub('\n', text)
    text = TRAIL.sub('', LEAD.sub('', text))
    text = LONE_PLUS.sub('', text)
    text = TRAIL.sub('', LEAD.sub('', text))
    return WHITESPACE.sub('', text)


def foreign_share(value: str, encoding: Optional[str]) -> float:
    """The share of the value's characters outside its encoding's alphabet; 0 when no encoding is declared."""
    if not encoding or not value:
        return 0.0
    alphabet = ALPHABETS[encoding]
    return sum(1 for char in value if char not in alphabet) / len(value)


def symbols(value: str, encoding: Optional[str]) -> int:
    """The number of symbols the value is drawn from: its encoding's, else read from the characters present."""
    if encoding:
        return SYMBOLS[encoding]
    if HEX.fullmatch(value):
        return 16
    if BASE32.fullmatch(value):
        return 32
    count = sum(size for pattern, size in CLASSES if pattern.search(value))
    count += len(set(ALPHANUMERIC.sub('', value)))
    return max(count, 2)


@lru_cache(maxsize=4096)
def expected_entropy(length: int, alphabet_size: int) -> float:
    """The Shannon entropy, in bits per character, a uniformly random string of this length over this many symbols is
    expected to show. Exact (each symbol's count is binomial) up to EXACT_UP_TO characters; beyond it the
    Miller–Madow approximation, which is within a thousandth of a bit there."""
    if length < 2 or alphabet_size < 2:
        return 0.0
    if length > EXACT_UP_TO:
        return log2(alphabet_size) - (alphabet_size - 1) / (2 * length * log(2))
    p = 1 / alphabet_size
    log_p, log_q, log_n = log(p), log1p(-p), lgamma(length + 1)
    mean = length * p
    per_symbol = 0.0
    for count in range(1, length + 1):
        pmf = exp(log_n - lgamma(count + 1) - lgamma(length - count + 1) + count * log_p + (length - count) * log_q)
        if count > mean and pmf < 1e-12:
            break
        share = count / length
        per_symbol -= pmf * share * log2(share)
    return alphabet_size * per_symbol


def randomness(value: str, entropy: float, encoding: Optional[str]) -> float:
    """The value's entropy over the entropy a random string of its length and alphabet is expected to have: about 1
    for a random value, lower for repetition and structure. The spread shrinks with length: a random 16-character value
    can fall to 0.8 by chance, a random 1,600-character key body stays above 0.98."""
    expected = expected_entropy(len(value), symbols(value, encoding))
    return entropy / expected if expected > 0 else 0.0


def checksum(value: str, encoding: Optional[str]) -> str:
    """'valid' or 'invalid' for an encoding that carries a checksum, else 'none'. base58check (Bitcoin WIF keys and
    addresses): the last 4 bytes are the first 4 of a double SHA-256 of the rest."""
    if encoding != 'base58check':
        return 'none'
    number = 0
    for char in value:
        digit = BASE58.find(char)
        if digit < 0:
            return 'invalid'
        number = number * 58 + digit
    raw = number.to_bytes((number.bit_length() + 7) // 8, 'big')
    raw = b'\0' * (len(value) - len(value.lstrip('1'))) + raw
    if len(raw) < 5:
        return 'invalid'
    body, check = raw[:-4], raw[-4:]
    return 'valid' if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == check else 'invalid'
