import bisect
from typing import Callable, List, Sequence, Set

from ordered_set import OrderedSet

from deepsecrets.core.model.semantic import Variable
from deepsecrets.core.model.token import Semantic, SemanticType, Token
from deepsecrets.core.model.tokenized_region import TokenizedRegion
from deepsecrets.core.tokenizers.helpers.semantic.language import Language
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.rules import (
    VariableDetectionRules,
    VariableSuppressionRules,
)
from deepsecrets.core.tokenizers.helpers.token_table import LazyTokens
from deepsecrets.core.tokenizers.helpers.type_stream import is_filtered_ttype, is_filtered_type

empty_tokens = ['\n', '\t', "'", "''", '"', '""']


class DeepAnalyzer:

    regions: List[TokenizedRegion]
    deep_inspection: bool
    post_filter: bool
    silent_regions: List

    def __init__(self, regions: List[TokenizedRegion], post_filter: bool, deep_inspection: bool = True) -> None:
        self.regions = regions
        self.deep_inspection = deep_inspection
        self.post_filter = post_filter
        self.silent_regions = []

    def get_final_tokens(self):
        tokens = []

        if self.deep_inspection is True:  # type: ignore
            self.run()

        [tokens.extend(region.tokens) for region in sorted(self.regions, key=lambda x: x.substitute_start_index)]
        return tokens

    def run(self):
        for region in self.regions:
            updated_tokens = []
            tokens_to_be_excluded = self.analyze_token_sequence(region.language, region.tokens, region.stream)
            updated_tokens.extend(
                self.final_cleanup(region.tokens, tokens_to_be_excluded) if self.post_filter else list(region.tokens)
            )
            region.tokens = updated_tokens

    def analyze_token_sequence(self, language: Language, tokens: List[Token], stream: str) -> Set[Token]:
        if language is None:
            return OrderedSet(tokens)

        exclude_after = set()

        true_var_detections: List[Variable] = []
        suppression_regions: List[List[int]] = []

        detection_rules = VariableDetectionRules.for_language(language)
        suppression_rules = VariableSuppressionRules.for_language(language)

        for rule in detection_rules:
            true_var_detections.extend(rule.match(tokens, stream))

        for rule in suppression_rules:
            suppression_regions.extend(rule.match(tokens, stream))

        suppression_regions = self._collapse_suppression_regions(suppression_regions)
        self.silent_regions.append(suppression_regions)
        is_suppressed = self._suppression_index(suppression_regions)

        for var in true_var_detections:
            suppressed = is_suppressed(var)
            if suppressed:
                exclude_after.update([var.name_token, var.value_token])
                continue

            var.value_token.semantic = Semantic(
                type=SemanticType.VARIABLE,
                # name=var.name.content,
                payload=var,
                creds_probability=var.found_by.creds_probability,
            )

            if var.name_token is not None:
                exclude_after.add(var.name_token)

        return exclude_after

    def _if_suppressed(self, var: Variable, regions):
        for reg in regions:
            if var.span[0] >= reg[0] and var.span[1] <= reg[1]:
                return True
        return False

    def _suppression_index(self, regions) -> Callable[[Variable], bool]:
        # Same answer as _if_suppressed ("some region contains the variable's span") in O(log regions):
        # among regions starting at or before the variable, the one reaching furthest decides.
        # A scan per variable was O(variables x regions), which dominated large flat JSON files.
        ordered = sorted(regions, key=lambda reg: reg[0])
        starts = [reg[0] for reg in ordered]
        furthest_ends: List[int] = []
        for reg in ordered:
            furthest_ends.append(reg[1] if not furthest_ends or reg[1] > furthest_ends[-1] else furthest_ends[-1])

        def is_suppressed(var: Variable) -> bool:
            index = bisect.bisect_right(starts, var.span[0]) - 1
            return index >= 0 and furthest_ends[index] >= var.span[1]

        return is_suppressed

    def _collapse_suppression_regions(self, suppression_regions):
        regions = []
        if len(suppression_regions) == 0:
            return regions

        for i, reg in enumerate(suppression_regions):
            if i == 0:
                regions.append(suppression_regions[0])
                continue

            if reg[0] == regions[-1][1]:
                regions[-1][1] = reg[1]
            else:
                regions.append(reg)

        return regions

    def final_cleanup(self, tokens_all: Sequence[Token], tokens_to_be_excluded: Sequence[Token]) -> List[Token]:
        if isinstance(tokens_all, LazyTokens):
            return self._final_cleanup_rows(tokens_all, tokens_to_be_excluded)

        # a list or ordered set: only the eager reference tokenizer in tests passes one, the lexer passes LazyTokens
        if not isinstance(tokens_all, OrderedSet):
            tokens_all = OrderedSet(tokens_all)

        tokens_all = tokens_all - tokens_to_be_excluded
        final = []
        for token in tokens_all:
            if is_filtered_type(token.type):
                continue

            if token.content.replace(' ', '') in empty_tokens:
                continue

            final.append(token)

        return final

    def _final_cleanup_rows(self, tokens: LazyTokens, tokens_to_be_excluded: Sequence[Token]) -> List[Token]:
        """`final_cleanup` over a lazy view, building only the tokens it keeps. A row nothing has read yet was never
        handed out, so it cannot be excluded, and its type and content decide it."""
        table = tokens.table
        final = []
        for index in range(tokens.start, tokens.stop):
            token = table.built[index]
            if token is None:
                if is_filtered_ttype(table.ttypes[index]):  # type: ignore
                    continue

                if table.contents[index].replace(' ', '') in empty_tokens:
                    continue

                final.append(table.token(index))
                continue

            if token in tokens_to_be_excluded:
                continue

            if is_filtered_type(token.type):
                continue

            if token.content.replace(' ', '') in empty_tokens:
                continue

            final.append(token)

        return final
