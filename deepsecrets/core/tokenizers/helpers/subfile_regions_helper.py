import regex as re
from typing import List
from deepsecrets.core.model.file import File
from deepsecrets.core.model.semantic import Region
from deepsecrets.core.model.token import Token
from deepsecrets.core.model.tokenized_region import TokenizedRegion
from deepsecrets.core.tokenizers.helpers.semantic.language import Language
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.detector import Match, RegionDetector
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from pygments.token import Token as PygmentsToken

'''

'''


class SubfileDetectionRules:
    hint_to_lang = {'console': 'txt'}

    rules = [
        # Detecting code snippets inside named backticks
        # TODO: look at the text after the backtick, eq. ```java
        RegionDetector(
            language=Language.MARKDOWN,
            stream_pattern=re.compile('b(b)\\s(o+)\\s*b'),
            match_rules={},
            match_semantics={1: 'language', 2: 'code'},
        ),
        RegionDetector(
            language=Language.MARKDOWN,
            stream_pattern=re.compile('b(b)\n(\\X*?)b'),
            match_rules={},
            match_semantics={1: 'language', 2: 'code'},
        ),
        RegionDetector(
            language=Language.YAML,
            stream_pattern=re.compile('(p)(p)([\n|n]*)\n(n)', flags=re.MULTILINE | re.S),
            match_rules={
                1: Match(values=[re.compile('^:$')]),
                2: Match(
                    values=[re.compile('^|$')],
                    types=[PygmentsToken.Punctuation.Indicator],
                ),
                4: Match(types=[PygmentsToken.Name.Tag]),
            },
            match_semantics={3: 'code'},
        ),
    ]

    @classmethod
    def for_language(cls, language: Language) -> List[RegionDetector]:
        return list(filter(lambda x: x.language in [language, Language.ANY], cls.rules))


class SubFileRegionsHelper:

    language: Language
    tokens: List[Token]
    stream: str
    file: File
    regions: List[TokenizedRegion]

    def __init__(self, file: File, language: Language, tokens: List[Token], stream: str) -> None:
        self.language = language
        self.tokens = tokens
        self.stream = stream
        self.file = file
        self.regions = []

    def extract_subcontent(self, match: Region):

        start_offset = self.tokens[match.code[0]].span[0]
        end_offset = self.tokens[match.code[1]].span[0]
        language_hint = None
        if hasattr(match, 'language') is True:
            language_hint = self.tokens[match.language[0]].content
            language_hint = SubfileDetectionRules.hint_to_lang.get(language_hint, language_hint)

        new_content = self.file.content[start_offset:end_offset]
        quazi_file = File(path=None, content=new_content, extension=language_hint)
        nizer = LexerTokenizer(deep_token_inspection=False)
        nizer.tokenize(quazi_file, post_filter=False)
        return nizer.regions

    def find(self):
        detection_rules = SubfileDetectionRules.for_language(self.language)
        if len(detection_rules) == 0:
            self.add_region(self.language, self.tokens, self.stream)
            return self.regions

        for rule in detection_rules:
            matches = rule.match(self.tokens, self.stream)
            current_index = 0
            for match in matches:
                start_index = match.code[0]
                end_index = match.code[1]
                self.add_region(
                    self.language,
                    self.tokens[current_index:start_index],
                    self.stream[current_index:start_index],
                )

                regions = self.extract_subcontent(match)
                if len(regions) == 0:
                    continue

                for region in regions:
                    start_offset = self.tokens[start_index].span[0]
                    for token in region.tokens:
                        token.span = (start_offset + token.span[0], start_offset + token.span[1])
                        token.file = self.file

                    self.add_region(region.language, region.tokens, region.stream)
                    current_index = end_index

        if len(self.regions) == 0:
            self.add_region(self.language, self.tokens, self.stream)
            return self.regions

        return self.regions

    def add_region(self, lang, tokens, stream):
        self.regions.append(
            TokenizedRegion(
                language=lang,
                tokens=tokens,
                stream=stream,
            )
        )
