from typing import List, Type, Union


from deepsecrets.core.model.tokenized_region import TokenizedRegion
from deepsecrets.core.tokenizers.helpers.semantic.deep_analyzer import DeepAnalyzer
from deepsecrets.core.utils.log import logger

from pygments.lexers.special import Lexer
from pygments.token import Token as PygmentsToken

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers.semantic.language import Language
from deepsecrets.core.tokenizers.helpers.single_token_improver import SingleTokenImprover
from deepsecrets.core.tokenizers.helpers.type_stream import (
    token_to_typestream_item,
)
from deepsecrets.core.tokenizers.itokenizer import Tokenizer
from deepsecrets.core.utils.lexer_finder import LexerFinder


class LexerTokenizer(Tokenizer):
    token_stream: str
    lexer: Lexer
    language: Language = None
    regions: List[TokenizedRegion] = []

    def _get_types_for_token(self, token: PygmentsToken) -> List[Type]:  # type: ignore
        types = []
        types.append(token)
        if token.parent is not None:
            if token.parent == PygmentsToken:
                return types
            deep = self._get_types_for_token(token.parent)
            types.extend(deep)
        return types

    def sanitize(self, content: str) -> Union[str, bool]:
        quotes = ["'", "''", '"', '""']

        whitespace_cleaned = content.replace(' ', '')
        if 0 <= len(whitespace_cleaned) == 0:
            return False

        # some lexers (eq. TextLexer) leave \n
        # at the end of a Token
        if len(content) > 1 and content[-1] == '\n':
            content = content[:-1]

        if content[0] == content[-1]:
            if content[0] in quotes:
                content = content[1:-1]

        if content in quotes:
            return False

        return content

    def _find_lexer_for_file(self, file: File):
        lexer = LexerFinder().find(file=file)
        if lexer is not None and lexer.name == 'Text only':
            return None
        return lexer

    def tokenize(self, file: File, post_filter=True) -> List[Token]:
        self.token_stream = ''
        # TODO: don't trust the extension, use 'file' utility ?

        self.lexer = self._find_lexer_for_file(file)
        if not self.lexer:
            return self.tokens
        try:
            self.language: Language = Language.from_text(self.lexer.filenames[0])
        except (ValueError, IndexError):
            self.language: Language = Language.from_text(file.extension)
        except Exception as e:
            logger.exception(e)

        raw_tokens = list(self.lexer.get_tokens_unprocessed(file.content))
        single_token_improver = SingleTokenImprover(lang=self.language)

        current_position = 0
        # TODO: Token.Error creates millions of bullshit
        for offset, types, content in raw_tokens:
            types: List[Type] = self._get_types_for_token(types)
            start = current_position
            end = start + len(content)
            current_position = end
            if current_position >= file.length:
                continue

            try:
                content = self.sanitize(content)
                if not content:
                    continue

                span = file.get_span_for_string(content, between=[start - 1, end + 1])
                token = Token(file=file, content=content, span=span)
                token.set_type(types)

                improved_tokens = single_token_improver.improve(self.tokens, self.token_stream, token)

                self.tokens.extend(improved_tokens)
                self.add_to_token_stream(improved_tokens)
            except Exception as e:
                str(e)

            self.on_new_offset_processed(new_offset=offset / file.length)

        self.regions: List[TokenizedRegion] = SubFileRegionsHelper(
            file=file,
            language=self.language,
            tokens=self.tokens,
            stream=self.token_stream,
        ).find()

        self.tokens = DeepAnalyzer(
            regions=self.regions,
            deep_inspection=self.settings.deep_token_inspection,
            post_filter=post_filter,
        ).get_final_tokens()
        return self.tokens

    def add_to_token_stream(self, tokens: List[Token]) -> None:
        for token in tokens:
            self.token_stream += token_to_typestream_item(token=token)

    def print_token_type_stream(self) -> None:
        print(self.token_stream)


from deepsecrets.core.tokenizers.helpers.subfile_regions_helper import SubFileRegionsHelper
