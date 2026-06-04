import regex as re
from typing import List, Set
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
    regions: Set[TokenizedRegion]

    def __init__(self, file: File, language: Language, tokens: List[Token], stream: str) -> None:
        self.language = language
        self.tokens = tokens
        self.stream = stream
        self.file = file
        self.regions = set()

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
        regions = set()
        detection_rules = SubfileDetectionRules.for_language(self.language)
        if len(detection_rules) == 0:
            self.add_region(self.language, self.tokens, self.stream, 0, len(self.tokens))
            return self.regions

        for rule in detection_rules:
            matches = rule.match(self.tokens, self.stream)
            for match in matches:
                start_index = match.code[0]
                end_index = match.code[1]
                content_regions = self.extract_subcontent(match)
                if len(content_regions) == 0:
                    continue

                for content_region in content_regions:
                    start_offset = self.tokens[start_index].span[0]
                    for token in content_region.tokens:
                        token.span = (start_offset + token.span[0], start_offset + token.span[1])
                        token.file = self.file

                    regions.add(
                        TokenizedRegion(
                            content_region.language,
                            content_region.tokens,
                            content_region.stream,
                            substitute_start_index=start_index,
                            substitute_end_index=end_index,
                        )
                    )

        if len(regions) == 0:
            self.add_region(self.language, self.tokens, self.stream, 0, len(self.tokens))
            return self.regions

        self.merge_regions(regions)

        return self.regions

    def merge_regions(self, regions: Set[TokenizedRegion]):
        current_index = 0
        for region in sorted(regions, key=lambda x: x.substitute_start_index):
            self.add_region(
                lang=self.language,
                substitute_start_index=current_index,
                substitute_end_index=region.substitute_start_index,
                tokens=self.tokens[current_index : region.substitute_start_index],
                stream=self.stream[current_index : region.substitute_start_index],
            )
            self.add_region(
                region.language,
                region.tokens,
                region.stream,
                region.substitute_start_index,
                region.substitute_end_index,
            )
            current_index = region.substitute_end_index

        self.add_region(
            lang=self.language,
            substitute_start_index=current_index,
            substitute_end_index=len(self.tokens),
            tokens=self.tokens[current_index:],
            stream=self.stream[current_index:],
        )

    def add_region(self, lang, tokens, stream, substitute_start_index, substitute_end_index):
        self.regions.add(
            TokenizedRegion(
                language=lang,
                tokens=tokens,
                stream=stream,
                substitute_start_index=substitute_start_index,
                substitute_end_index=substitute_end_index,
            )
        )
