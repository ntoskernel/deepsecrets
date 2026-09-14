import regex as re
from typing import Callable, List

from pygments.token import Token as PygmentsToken

from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers.semantic.language import Language
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.detector import Match, RegionDetector
from deepsecrets.core.tokenizers.helpers.type_stream import token_to_typestream_item

# `curl -u <credentials>`: the token after a literal `-u`
CURL_CREDENTIALS_DETECTOR = RegionDetector(
    stream_pattern=re.compile('(L)(L)$'),
    match_rules={1: Match(values=[re.compile('^-u$')])},
    match_semantics={},
)


class SingleTokenImprover:
    language: Language
    acc: dict[Language, List[Callable]]

    def __init__(self, lang: Language) -> None:
        self.language = lang
        self.acc = {
            Language.SHELL: [self._curl_argstring_breakdown],
            # Language.PHP: [self._php_variable_dollar_sign_breakdown], # TODO: Uncomment in v2.1
        }

    def improve(self, so_far_tokens: List[Token], so_far_type_stream: str, current_token: Token) -> List[Token]:
        checkers: List[Callable] = self.acc.get(Language.ANY, [])
        checkers.extend(self.acc.get(self.language, []))

        tokens = []
        for improvement in checkers:
            tokens.extend(improvement(so_far_tokens, so_far_type_stream, current_token))

        if len(tokens) == 0:
            return [current_token]

        return tokens

    def _php_variable_dollar_sign_breakdown(
        self, so_far_tokens: List[Token], so_far_type_stream: str, current_token: Token
    ) -> List[Token]:
        target_token_type = PygmentsToken.Name.Variable
        if target_token_type not in current_token.type:
            return [current_token]

        if not current_token.content.startswith('$'):
            return [current_token]

        first_part = current_token.content[0]
        second_part = current_token.content[1:]

        final = []
        fp_token = Token(
            file=current_token.file,
            content=first_part,
            span=current_token.file.get_span_for_string(first_part, between=current_token.span),
        )
        fp_token.set_type([PygmentsToken.Operator])
        final.append(fp_token)

        sp_token = Token(
            file=current_token.file,
            content=second_part,
            span=current_token.file.get_span_for_string(first_part, between=current_token.span),
        )
        sp_token.set_type([PygmentsToken.Name.Variable])
        final.append(sp_token)

        return [fp_token, sp_token]

    def _curl_argstring_breakdown(
        self, so_far_tokens: List[Token], so_far_type_stream: str, current_token: Token
    ) -> List[Token]:
        # '(L)(L)$' can only match the last two stream items, or the two before a trailing newline,
        # so matching the tail (aligned with the last two tokens) is equivalent to matching the whole
        # stream, and keeps this O(1) per token instead of O(tokens so far).
        tail_length = min(2, len(so_far_tokens))
        tail_tokens = so_far_tokens[len(so_far_tokens) - tail_length :]
        projected_tail = so_far_type_stream[len(so_far_type_stream) - tail_length :]
        projected_tail += token_to_typestream_item(current_token)

        match = CURL_CREDENTIALS_DETECTOR.match(tail_tokens, projected_tail)
        if not match:
            return [current_token]

        new_parts = current_token.content.split(':')
        if new_parts[0] == '' or new_parts[1] == '':
            return [current_token]

        final = []
        for part in new_parts:
            t = Token(
                file=current_token.file,
                content=part,
                span=current_token.file.get_span_for_string(part, between=current_token.span),
            )
            t.set_type([PygmentsToken.Text])
            final.append(t)

        return final
