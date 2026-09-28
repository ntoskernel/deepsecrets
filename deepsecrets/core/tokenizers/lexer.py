from typing import List, Set, Union


from deepsecrets.core.model.tokenized_region import TokenizedRegion
from deepsecrets.core.tokenizers.helpers.semantic.deep_analyzer import DeepAnalyzer
from deepsecrets.core.utils.log import logger

from pygments.lexers.special import Lexer
from pygments.token import Token as PygmentsToken

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.helpers.semantic.language import Language
from deepsecrets.core.tokenizers.helpers.single_token_improver import SingleTokenImprover
from deepsecrets.core.tokenizers.helpers.token_table import LazyTokens, TokenTable
from deepsecrets.core.tokenizers.helpers.type_stream import stream_item, token_to_typestream_item, type_chain
from deepsecrets.core.tokenizers.itokenizer import Tokenizer
from deepsecrets.core.utils.lexer_finder import LexerFinder


class LexerTokenizer(Tokenizer):
    token_stream: str
    lexer: Lexer
    language: Language = None
    regions: Set[TokenizedRegion] = None

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
        self.regions = set()
        self.token_stream = ''
        # TODO: don't trust the extension, use 'file' utility ?

        self.lexer = self._find_lexer_for_file(file)
        if not self.lexer:
            # not the previous file's tokens, should this tokenizer be reused
            self.tokens = []
            return self.tokens
        try:
            self.language: Language = Language.from_text(self.lexer.filenames[0])
        except (ValueError, IndexError):
            self.language: Language = Language.from_text(file.extension)
        except Exception as e:
            logger.exception(e)

        # iterated once, as Pygments produces it: a list would hold every raw token of the file at once
        raw_tokens = self.lexer.get_tokens_unprocessed(file.content)
        single_token_improver = SingleTokenImprover(lang=self.language)
        improving = single_token_improver.applies()
        # Tokens are recorded as rows and built only when something reads them (see helpers/token_table.py).
        table = TokenTable(file)
        stream: List[str] = []

        current_position = 0
        # TODO: Token.Error creates millions of bullshit
        for offset, ttype, content in raw_tokens:
            types = type_chain(ttype)
            start = current_position
            end = start + len(content)
            current_position = end
            if current_position > file.length:
                continue

            try:
                if PygmentsToken.Error in types and len(types) == 1:
                    continue

                content = self.sanitize(content)
                if not content:
                    continue

                item = stream_item(ttype, content)
                parts = None
                if improving:
                    previous = ''.join(stream[-2:])
                    parts = single_token_improver.improve(ttype, content, item, previous, table.contents[-2:])

                if parts is None:
                    table.add(ttype, content, start, end)
                    stream.append(item)
                else:
                    self._add_parts(table, stream, content, start, end, parts)
            except Exception as e:
                str(e)

            self.on_new_offset_processed(new_offset=current_position / file.length)

        self.tokens = LazyTokens(table)
        self.token_stream = ''.join(stream)

        self.regions: Set[TokenizedRegion] = SubFileRegionsHelper(
            file=file,
            language=self.language,
            tokens=self.tokens,
            stream=self.token_stream,
        ).find()

        deep_analyzer = DeepAnalyzer(
            regions=self.regions,
            deep_inspection=self.settings.deep_token_inspection,
            post_filter=post_filter,
        )
        self.tokens = deep_analyzer.get_final_tokens()
        self.silent_regions = deep_analyzer.silent_regions
        return self.tokens

    def _add_parts(self, table: TokenTable, stream: List[str], content: str, start: int, end: int, parts) -> None:
        """The tokens an improvement split a token into, searched for inside the span the whole token would have had.
        No parts drops the token."""
        file = table.file
        span = file.get_span_for_string(content, between=[start - 1, end + 1])
        for part, part_type in parts:
            token = Token(file=file, content=part, span=file.get_span_for_string(part, between=span))
            token.set_type([part_type])
            table.add_token(token)
            stream.append(token_to_typestream_item(token=token))

    def print_token_type_stream(self) -> None:
        print(self.token_stream)


from deepsecrets.core.tokenizers.helpers.subfile_regions_helper import SubFileRegionsHelper
