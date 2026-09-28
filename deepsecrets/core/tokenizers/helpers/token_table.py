"""The lexer's tokens as rows, built into `Token` objects only when something reads them.

Most tokens a lexer produces are punctuation, operators, names and masked types that the type stream needs but
`DeepAnalyzer.final_cleanup` drops by type alone. `LexerTokenizer` therefore records each token as a row (Pygments
type, sanitised content, raw offsets) and hands out `LazyTokens` views over the table. Reading an index builds that
row's `Token`, with the span and type chain an eager build would give it, and caches it: a token keeps one identity
for the life of the table, which `DeepAnalyzer`'s identity-based exclusions rely on.
"""

from collections.abc import Sequence
from typing import Iterator, List, Optional

from pygments.token import _TokenType

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers.type_stream import type_chain


class TokenTable:
    file: File
    ttypes: List[Optional[_TokenType]]
    contents: List[str]
    starts: List[int]
    ends: List[int]
    built: List[Optional[Token]]

    def __init__(self, file: File) -> None:
        self.file = file
        self.ttypes = []
        self.contents = []
        self.starts = []
        self.ends = []
        self.built = []

    def __len__(self) -> int:
        return len(self.contents)

    def add(self, ttype: _TokenType, content: str, start: int, end: int) -> None:
        """A lexer token: `content` is sanitised, `start` and `end` are the raw token's offsets in the file."""
        self.ttypes.append(ttype)
        self.contents.append(content)
        self.starts.append(start)
        self.ends.append(end)
        self.built.append(None)

    def add_token(self, token: Token) -> None:
        """A token that already exists, such as a part `SingleTokenImprover` split off."""
        self.ttypes.append(None)
        self.contents.append(token.content)
        self.starts.append(-1)
        self.ends.append(-1)
        self.built.append(token)

    def token(self, index: int) -> Token:
        token = self.built[index]
        if token is None:
            content = self.contents[index]
            # the span is searched for within one character of the raw token, as the tokenizer always did
            span = self.file.get_span_for_string(content, between=[self.starts[index] - 1, self.ends[index] + 1])
            token = Token(file=self.file, content=content, span=span)
            token.set_type(list(type_chain(self.ttypes[index])))  # type: ignore
            self.built[index] = token
        return token


class LazyTokens(Sequence):
    """A read-only list of the table's rows `start` to `stop`: an index builds that row's token, a slice with step 1
    is a view (any other step gives a list)."""

    __slots__ = ('table', 'start', 'stop')

    def __init__(self, table: TokenTable, start: int = 0, stop: Optional[int] = None) -> None:
        self.table = table
        self.start = start
        self.stop = len(table) if stop is None else stop

    def __len__(self) -> int:
        return self.stop - self.start

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(len(self))
            if step == 1:
                return LazyTokens(self.table, self.start + start, self.start + max(start, stop))
            return [self.table.token(self.start + i) for i in range(start, stop, step)]

        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError('token index out of range')
        return self.table.token(self.start + index)

    def __iter__(self) -> Iterator[Token]:
        for index in range(self.start, self.stop):
            yield self.table.token(index)

    def __repr__(self) -> str:  # pragma: no cover
        return f'LazyTokens(rows {self.start} to {self.stop} of {len(self.table)})'
