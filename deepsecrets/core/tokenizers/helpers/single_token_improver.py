import regex as re
from typing import Callable, List, Optional, Sequence, Tuple

from pygments.token import Token as PygmentsToken, _TokenType

from deepsecrets.core.tokenizers.helpers.semantic.language import Language
from deepsecrets.core.tokenizers.helpers.type_stream import type_chain

# A piece the current token is split into: its content and the Pygments type it gets.
Part = Tuple[str, _TokenType]

CURL_CREDENTIALS_FLAG = re.compile('^-u$')


class SingleTokenImprover:
    """Splits one lexer token into several in known cases.

    An improvement decides from the current token (Pygments type, sanitised content, type-stream item) and the two
    tokens before it as the tokenizer has emitted them (their stream items and contents), so the tokenizer never has
    to build a `Token` to ask. It returns None to keep the token, or the parts that replace it, in order.
    """

    language: Language
    acc: dict[Language, List[Callable]]

    def __init__(self, lang: Language) -> None:
        self.language = lang
        self.acc = {
            Language.SHELL: [self._curl_argstring_breakdown],
            # Language.PHP: [self._php_variable_dollar_sign_breakdown],  # off: it would change PHP tokens (KI-TOK-31)
        }

    def applies(self) -> bool:
        """Whether `improve` can change anything for this language; if not, it keeps every token."""
        return bool(self.acc.get(Language.ANY) or self.acc.get(self.language))

    def improve(
        self, ttype: _TokenType, content: str, item: str, previous_items: str, previous_contents: Sequence[str]
    ) -> Optional[List[Part]]:
        """`previous_items` and `previous_contents` hold at most the two tokens emitted before this one."""
        for improvement in self.acc.get(Language.ANY, []) + self.acc.get(self.language, []):
            parts = improvement(ttype, content, item, previous_items, previous_contents)
            if parts is not None:
                return parts
        return None

    def _php_variable_dollar_sign_breakdown(
        self, ttype: _TokenType, content: str, item: str, previous_items: str, previous_contents: Sequence[str]
    ) -> Optional[List[Part]]:
        if PygmentsToken.Name.Variable not in type_chain(ttype):
            return None

        if not content.startswith('$'):
            return None

        return [(content[0], PygmentsToken.Operator), (content[1:], PygmentsToken.Name.Variable)]

    def _curl_argstring_breakdown(
        self, ttype: _TokenType, content: str, item: str, previous_items: str, previous_contents: Sequence[str]
    ) -> Optional[List[Part]]:
        # `curl -u <credentials>`: a plain word (`L`) right after a literal `-u`, split on ':' into user and password.
        after_flag = (
            item == 'L'
            and previous_items[-1:] == 'L'
            and CURL_CREDENTIALS_FLAG.match(previous_contents[-1]) is not None
        )
        # Kept from the stream regex '(L)(L)$' this replaced: its `$` also matched before a final newline, so a
        # newline two tokens after `-u` counts as the credentials too (and is dropped below: it has no ':').
        before_newline = (
            item == '\n'
            and previous_items[-2:] == 'LL'
            and CURL_CREDENTIALS_FLAG.match(previous_contents[-2]) is not None
        )
        if not (after_flag or before_newline):
            return None

        new_parts = content.split(':')
        if len(new_parts) == 1:
            # Dropped, as before this was rewritten: indexing the missing second part raised, and the tokenizer skips
            # a token that raises. The dropped token never becomes "the token before", so the next word is judged
            # against `-u` again: one without ':' is dropped too, one with ':' is split as the credentials
            # (`curl -u admin https://x` reports `https` = `//x`). KI-TOK-01.
            return []

        if new_parts[0] == '' or new_parts[1] == '':
            return None

        return [(part, PygmentsToken.Text) for part in new_parts]
