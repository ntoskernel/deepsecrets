from enum import Enum
from deepsecrets.core.model.rules.regex import RegexRule
from deepsecrets.core.model.semantic import Context
import regex as re


class Target(str, Enum):
    NAME_SPACED = "NAME_SPACED"  # "api access key"
    NAME_NORMALIZED = "NAME_NORMALIZED"  # "apiaccesskey" (Best for fuzzy)
    VALUE = "VALUE"
    FILEPATH = "FILEPATH"  # The file path


target_to_fields = {
    Target.FILEPATH: 'filepath',
    Target.NAME_SPACED: 'name_spaced',
    Target.VALUE: 'value',
    Target.NAME_NORMALIZED: 'name_normalized',
}


class VariableScoringRule(RegexRule):
    score: int
    target: Target

    def _get_content_for_matching(self, context: Context):
        field = target_to_fields.get(self.target)
        return getattr(context, field)

    def match_by_context(self, context: Context) -> bool:
        content = self._get_content_for_matching(context)
        match = re.search(self.pattern, content)
        if match is not None:
            return True
        return False
