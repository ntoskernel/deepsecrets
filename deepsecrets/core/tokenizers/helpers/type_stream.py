from typing import Dict, Sequence, Tuple

from pygments.token import Token as PygmentsToken, _TokenType

from deepsecrets.core.model.token import Token

types_to_filter_before = [
    PygmentsToken.Text.Whitespace,
    PygmentsToken.Error,
    PygmentsToken.Keyword,
    PygmentsToken.Generic,
    PygmentsToken.Literal.Date,
    PygmentsToken.Literal.Number,
    PygmentsToken.Literal.String.Char,
    PygmentsToken.Literal.String.Delimiter,
    PygmentsToken.Literal.String.Escape,
    PygmentsToken.Literal.String.Affix,
    PygmentsToken.Literal.String.Interpol,
    PygmentsToken.Comment.Hashbang,
    PygmentsToken.Name.Namespace,
    PygmentsToken.Name.Builtin.Pseudo,
]

types_not_to_filter_before = [
    PygmentsToken.Generic.Output,
]


types_to_filter_after = [
    PygmentsToken.Punctuation,
    PygmentsToken.Operator,
    PygmentsToken.Name,
]


acc = {
    PygmentsToken.Operator: 'o',
    PygmentsToken.Name: 'n',
    PygmentsToken.Name.Variable: 'v',
    PygmentsToken.Name.Variable.Global: 'v',
    PygmentsToken.Name.Variable.Instance: 'v',
    PygmentsToken.Name.Variable.Magic: 'v',
    PygmentsToken.Name.Other: 'n',
    PygmentsToken.Name.Tag: 'n',
    PygmentsToken.Name.Constant: 'n',
    PygmentsToken.Name.Attribute: 'n',
    PygmentsToken.Keyword.Constant: 'k',
    PygmentsToken.Punctuation: 'p',
    PygmentsToken.Punctuation.Indicator: 'p',
    PygmentsToken.Literal: 'L',
    PygmentsToken.Literal.Scalar.Plain: 'L',
    PygmentsToken.Literal.String: 'L',
    PygmentsToken.Literal.String.Symbol: 'L',
    PygmentsToken.String: 'L',
    PygmentsToken.String.Single: 'L',
    PygmentsToken.String.Double: 'L',
    PygmentsToken.Text: 'L',
    PygmentsToken.Literal.String.Backtick: 'b',  # technically it's a punc
    PygmentsToken.Generic.Output: 'o',
}


def token_to_typestream_item(token: Token) -> str:
    if token.content == '\n':
        return '\n'

    if any(type in token.type for type in types_to_filter_before) and not any(type in token.type for type in types_not_to_filter_before):  # type: ignore
        return 'u'

    return acc.get(token.type[0], '?')  # type: ignore


# The tables below depend only on a token's Pygments type (and, for the stream item, on whether its content is a
# newline), so they are filled once per type rather than once per token.
_chains: Dict[_TokenType, Tuple[_TokenType, ...]] = {}
_stream_items: Dict[_TokenType, str] = {}
_dropped: Dict[_TokenType, bool] = {}


def type_chain(ttype: _TokenType) -> Tuple[_TokenType, ...]:
    """The type and its parents, most specific first, without the root `Token`: what `Token.type` holds."""
    chain = _chains.get(ttype)
    if chain is None:
        types = [ttype]
        while types[-1].parent is not None and types[-1].parent != PygmentsToken:
            types.append(types[-1].parent)
        chain = _chains[ttype] = tuple(types)
    return chain


def stream_item(ttype: _TokenType, content: str) -> str:
    """`token_to_typestream_item` for a token of this type and content, without building the token."""
    if content == '\n':
        return '\n'

    item = _stream_items.get(ttype)
    if item is None:
        chain = type_chain(ttype)
        masked = any(type in chain for type in types_to_filter_before) and not any(
            type in chain for type in types_not_to_filter_before
        )
        item = _stream_items[ttype] = 'u' if masked else acc.get(ttype, '?')
    return item


def is_filtered_type(types: Sequence[_TokenType]) -> bool:
    """The type half of `DeepAnalyzer.final_cleanup`: masked types and the stream's structure are both dropped."""
    return any(type in types for type in types_to_filter_before) or any(type in types for type in types_to_filter_after)


def is_filtered_ttype(ttype: _TokenType) -> bool:
    """`is_filtered_type` for a token that still has the type chain of its Pygments type."""
    dropped = _dropped.get(ttype)
    if dropped is None:
        dropped = _dropped[ttype] = is_filtered_type(type_chain(ttype))
    return dropped
